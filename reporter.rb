    def get_os_info
        begin
            os_release = read_file('/etc/os-release') 
        rescue Rex::Post::Meterpreter::RequestError => e
            print_error("Could not read /etc/os-release: #{e}")
            os_release = nil
        end
        return nil unless os_release

            os_info = {}
            os_release.each_line do |line|
            key, value = line.strip.split('=')
            os_info[key] = value.delete('"') if key && value
        end
        os_info
    end

    puts(get_os_info)