require 'open3'

class MultipassScannerWorker
  include Sidekiq::Worker
  sidekiq_options :queue => :lomem_slow
  
  def perform(id, host, ports, opts)
    full_options = ['nmap', '-oX', '-', '-p', ports, opts, host].flatten
    stdout_str, stderr_str, status = Open3.capture3(*full_options)
    if status == 0
      Sidekiq::Client.enqueue(MultipassScannerResults, id, stdout_str, false)
    else
      # nmap didn't finish properly (probably killed), try again later.
      # should this be a real error class?
      raise "nmap died. status: #{status}, error: #{stderr_str}"
    end
  end
end
