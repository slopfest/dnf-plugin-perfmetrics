// This libdnf5 plugin captures timing metrics for DNF5 operations, associates
// transaction details, and serializes the record into a JSON file in
// /var/log/dnf5/perfmetrics.
//
// Per-event timers are reconstructed from the libdnf5 plugin hook boundaries:
//   repo_load_time      post_base_setup -> repos_loaded
//   depsolve_time       repos_loaded    -> goal_resolved
//   rpm_transaction_time pre_transaction -> post_transaction
//   full_command_time   plugin construction -> post_transaction
//
// This replaces the DNF4 Python plugin, which scraped "timer: <event>: <ms>"
// log messages emitted by dnf.logging.Timer -- a mechanism that has no
// equivalent in DNF5.

#include <json.h>
#include <unistd.h>

#include <libdnf5/base/base.hpp>
#include <libdnf5/base/transaction.hpp>
#include <libdnf5/base/transaction_package.hpp>
#include <libdnf5/conf/config_parser.hpp>
#include <libdnf5/logger/logger.hpp>
#include <libdnf5/plugin/iplugin.hpp>
#include <libdnf5/rpm/package.hpp>
#include <libdnf5/transaction/transaction_item_action.hpp>
#include <libdnf5/version.hpp>

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <exception>
#include <filesystem>
#include <fstream>
#include <optional>
#include <string>
#include <vector>

using namespace libdnf5;

namespace {

constexpr const char * PLUGIN_NAME = "perfmetrics";
constexpr plugin::Version PLUGIN_VERSION{1, 0, 0};

// The plugin only relies on hooks available in API 2.1 (notably goal_resolved
// from IPlugin2_1). This must not exceed the API version implemented by the
// loaded library.
constexpr PluginAPIVersion REQUIRED_PLUGIN_API_VERSION{.major = 2, .minor = 1};

constexpr const char * attrs[]{"author.name", "author.email", "description", nullptr};
constexpr const char * attrs_value[]{
    "Davide Cavalca", "dcavalca@meta.com", "Records DNF5 performance metrics to JSON."};

constexpr const char * DEFAULT_METRICS_DIR = "/var/log/dnf5/perfmetrics";
constexpr int DEFAULT_RETENTION_HOURS = 4;

using SteadyClock = std::chrono::steady_clock;

// Reads /proc/self/cmdline (NUL-separated arguments) into a vector of strings.
std::vector<std::string> read_cmdline() {
    std::vector<std::string> args;
    std::ifstream f("/proc/self/cmdline", std::ios::binary);
    std::string arg;
    char c;
    while (f.get(c)) {
        if (c == '\0') {
            args.push_back(arg);
            arg.clear();
        } else {
            arg.push_back(c);
        }
    }
    if (!arg.empty()) {
        args.push_back(arg);
    }
    return args;
}

// Parses /proc/<pid>/status, returning the process name (Name:) and parent pid
// (PPid:). Returns false if the status file cannot be read.
bool read_proc_status(pid_t pid, std::string & name, pid_t & ppid) {
    std::ifstream f("/proc/" + std::to_string(pid) + "/status");
    if (!f) {
        return false;
    }
    name.clear();
    ppid = 0;
    std::string line;
    while (std::getline(f, line)) {
        if (line.rfind("Name:", 0) == 0) {
            auto pos = line.find_first_not_of(" \t", 5);
            name = pos == std::string::npos ? "" : line.substr(pos);
        } else if (line.rfind("PPid:", 0) == 0) {
            auto pos = line.find_first_not_of(" \t", 5);
            ppid = pos == std::string::npos ? 0 : static_cast<pid_t>(std::stol(line.substr(pos)));
        }
    }
    return true;
}

// Builds the process tree (parents of the current process up to init), ordered
// from init down to the current process, mirroring the DNF4 plugin.
std::vector<std::string> build_process_tree() {
    std::vector<std::string> tree;
    pid_t pid = getpid();
    // Bound the walk to avoid looping on malformed /proc data.
    for (int depth = 0; depth < 256 && pid > 0; ++depth) {
        std::string name;
        pid_t ppid = 0;
        if (!read_proc_status(pid, name, ppid)) {
            break;
        }
        tree.push_back(name);
        if (pid == 1 || ppid == 0) {
            break;
        }
        pid = ppid;
    }
    std::reverse(tree.begin(), tree.end());
    return tree;
}

int64_t elapsed_ms(SteadyClock::time_point start, SteadyClock::time_point end) {
    return std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
}


class PerfMetrics final : public plugin::IPlugin2_1 {
public:
    PerfMetrics(libdnf5::plugin::IPluginData & data, libdnf5::ConfigParser & parser) : IPlugin2_1(data) {
        full_command_start = SteadyClock::now();

        if (parser.has_option("main", "metrics_dir")) {
            metrics_dir = parser.get_value("main", "metrics_dir");
        }
        if (parser.has_option("main", "retention_hours")) {
            retention_hours = std::stoi(parser.get_value("main", "retention_hours"));
        }

        command_args = read_cmdline();
        process_tree = build_process_tree();
    }

    virtual ~PerfMetrics() = default;

    PluginAPIVersion get_api_version() const noexcept override { return REQUIRED_PLUGIN_API_VERSION; }

    const char * get_name() const noexcept override { return PLUGIN_NAME; }

    plugin::Version get_version() const noexcept override { return PLUGIN_VERSION; }

    const char * const * get_attributes() const noexcept override { return attrs; }

    const char * get_attribute(const char * attribute) const noexcept override {
        for (size_t i = 0; attrs[i]; ++i) {
            if (std::strcmp(attribute, attrs[i]) == 0) {
                return attrs_value[i];
            }
        }
        return nullptr;
    }

    void post_base_setup() override { base_setup_done = SteadyClock::now(); }

    void repos_loaded() override { repos_loaded_done = SteadyClock::now(); }

    void goal_resolved(const libdnf5::base::Transaction &) override { goal_resolved_done = SteadyClock::now(); }

    void pre_transaction(const libdnf5::base::Transaction & transaction) override {
        transaction_start = SteadyClock::now();
        collect_package_actions(transaction);
    }

    void post_transaction(const libdnf5::base::Transaction & transaction) override {
        const auto now = SteadyClock::now();

        if (package_actions.empty()) {
            // pre_transaction is not always invoked (e.g. a download-only run);
            // capture the package list here as a fallback.
            collect_package_actions(transaction);
        }

        full_command_time = elapsed_ms(full_command_start, now);
        if (base_setup_done && repos_loaded_done) {
            repo_load_time = elapsed_ms(*base_setup_done, *repos_loaded_done);
        }
        if (repos_loaded_done && goal_resolved_done) {
            depsolve_time = elapsed_ms(*repos_loaded_done, *goal_resolved_done);
        }
        if (transaction_start) {
            rpm_transaction_time = elapsed_ms(*transaction_start, now);
        }

        // We can only write the logs and clean up as root.
        if (geteuid() != 0) {
            return;
        }
        write_results();
        cleanup_old_logs();
    }

private:
    struct PackageAction {
        std::string name;
        std::string arch;
        std::string epoch;
        std::string version;
        std::string release;
        std::string action;
        unsigned long long package_size;
        unsigned long long install_size;
    };

    void collect_package_actions(const libdnf5::base::Transaction & transaction) {
        package_actions.clear();
        for (const auto & tp : transaction.get_transaction_packages()) {
            auto pkg = tp.get_package();
            package_actions.push_back(
                {pkg.get_name(),
                 pkg.get_arch(),
                 pkg.get_epoch(),
                 pkg.get_version(),
                 pkg.get_release(),
                 libdnf5::transaction::transaction_item_action_to_letter(tp.get_action()),
                 pkg.get_download_size(),
                 pkg.get_install_size()});
        }
    }

    // Serializes the collected metrics into a json-c object. Caller owns the
    // returned object and must json_object_put() it.
    json_object * build_json() const {
        json_object * root = json_object_new_object();

        json_object * args = json_object_new_array();
        for (const auto & a : command_args) {
            json_object_array_add(args, json_object_new_string(a.c_str()));
        }
        json_object_object_add(root, "command_args", args);

        json_object * tree = json_object_new_array();
        for (const auto & p : process_tree) {
            json_object_array_add(tree, json_object_new_string(p.c_str()));
        }
        json_object_object_add(root, "process_tree", tree);

        json_object * pkgs = json_object_new_array();
        for (const auto & pa : package_actions) {
            json_object * o = json_object_new_object();
            json_object_object_add(o, "name", json_object_new_string(pa.name.c_str()));
            json_object_object_add(o, "arch", json_object_new_string(pa.arch.c_str()));
            json_object_object_add(o, "epoch", json_object_new_string(pa.epoch.c_str()));
            json_object_object_add(o, "version", json_object_new_string(pa.version.c_str()));
            json_object_object_add(o, "release", json_object_new_string(pa.release.c_str()));
            json_object_object_add(o, "action", json_object_new_string(pa.action.c_str()));
            json_object_object_add(o, "package_size", json_object_new_int64(static_cast<int64_t>(pa.package_size)));
            json_object_object_add(o, "install_size", json_object_new_int64(static_cast<int64_t>(pa.install_size)));
            json_object_array_add(pkgs, o);
        }
        json_object_object_add(root, "package_actions", pkgs);

        if (repo_load_time) {
            json_object_object_add(root, "repo_load_time", json_object_new_int64(*repo_load_time));
        }
        if (depsolve_time) {
            json_object_object_add(root, "depsolve_time", json_object_new_int64(*depsolve_time));
        }
        if (rpm_transaction_time) {
            json_object_object_add(root, "rpm_transaction_time", json_object_new_int64(*rpm_transaction_time));
        }
        if (full_command_time) {
            json_object_object_add(root, "full_command_time", json_object_new_int64(*full_command_time));
        }

        return root;
    }

    void write_results() const {
        std::error_code ec;
        std::filesystem::create_directories(metrics_dir, ec);
        if (ec) {
            get_base().get_logger()->error(
                "perfmetrics: cannot create metrics directory \"{}\": {}", metrics_dir, ec.message());
            return;
        }

        const auto now = std::chrono::system_clock::now();
        const double now_secs =
            std::chrono::duration<double>(now.time_since_epoch()).count();
        const auto filename = std::filesystem::path(metrics_dir) /
            ("perfmetrics-" + std::to_string(now_secs) + "_" + std::to_string(getpid()) + ".json");

        json_object * root = build_json();
        const char * text =
            json_object_to_json_string_ext(root, JSON_C_TO_STRING_PRETTY | JSON_C_TO_STRING_NOSLASHESCAPE);

        std::ofstream out(filename);
        if (out) {
            out << text << "\n";
        } else {
            get_base().get_logger()->error(
                "perfmetrics: error writing performance metrics to file {}", filename.string());
        }
        json_object_put(root);
    }

    void cleanup_old_logs() const {
        const auto cutoff =
            std::filesystem::file_time_type::clock::now() - std::chrono::hours(retention_hours);
        std::error_code ec;
        for (const auto & entry : std::filesystem::directory_iterator(metrics_dir, ec)) {
            std::error_code stat_ec;
            const auto mtime = std::filesystem::last_write_time(entry.path(), stat_ec);
            if (!stat_ec && mtime < cutoff) {
                std::filesystem::remove(entry.path(), stat_ec);
            }
        }
    }

    std::string metrics_dir = DEFAULT_METRICS_DIR;
    int retention_hours = DEFAULT_RETENTION_HOURS;

    std::vector<std::string> command_args;
    std::vector<std::string> process_tree;
    std::vector<PackageAction> package_actions;

    SteadyClock::time_point full_command_start;
    std::optional<SteadyClock::time_point> base_setup_done;
    std::optional<SteadyClock::time_point> repos_loaded_done;
    std::optional<SteadyClock::time_point> goal_resolved_done;
    std::optional<SteadyClock::time_point> transaction_start;

    std::optional<int64_t> repo_load_time;
    std::optional<int64_t> depsolve_time;
    std::optional<int64_t> rpm_transaction_time;
    std::optional<int64_t> full_command_time;
};

std::exception_ptr last_exception;

}  // namespace

PluginAPIVersion libdnf_plugin_get_api_version(void) {
    return REQUIRED_PLUGIN_API_VERSION;
}

const char * libdnf_plugin_get_name(void) {
    return PLUGIN_NAME;
}

plugin::Version libdnf_plugin_get_version(void) {
    return PLUGIN_VERSION;
}

plugin::IPlugin * libdnf_plugin_new_instance(
    [[maybe_unused]] LibraryVersion library_version,
    libdnf5::plugin::IPluginData & data,
    libdnf5::ConfigParser & parser) try {
    return new PerfMetrics(data, parser);
} catch (...) {
    last_exception = std::current_exception();
    return nullptr;
}

void libdnf_plugin_delete_instance(plugin::IPlugin * plugin_object) {
    delete plugin_object;
}

std::exception_ptr * libdnf_plugin_get_last_exception(void) {
    return &last_exception;
}
