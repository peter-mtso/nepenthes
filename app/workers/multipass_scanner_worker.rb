require 'open3'

class MultipassScannerWorker
  include Sidekiq::Worker
  sidekiq_options :queue => :lomem_slow
  
  def perform(id, host, ports, opts)
    full_options = ['nmap', '-oX', '-', '-p', ports, opts, host].flatten
    stdout_str, status = Open3.capture2(*full_options)
    if status == 0
      Sidekiq::Client.enqueue(MultipassScannerResults, id, stdout_str, false)
    else
      # nmap didn't finish properly (probably killed), try again later.
      logger.info { "nmap died, status: #{status}" }
      Sidekiq::Client.enqueue(MultipassScannerWorker, id, host, ports, opts)
    end
  end
end
