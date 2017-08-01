class MultipassScan < ActiveRecord::Base
  belongs_to :ip_address
  attr_accessible :options, :ports
  serialize :options
  serialize :ports, JSON

  def process!
    return if self.processed

    doc = Nokogiri::XML(self.results)
    unless doc.at('/nmaprun/host/address/@addr')
      throw "no result found"
      # original Scan model enqueued another scan in this case.
      # not sure when it would be triggered -- nmap dies somehow?
      # dunno if throwing is reasonable either...
    end

    doc.xpath('/nmaprun/host').each do |host|
      # not actually designed to run for multiple hosts
      ip_address = IpAddress.find_by_dotted(host.at('address/@addr').value)
      return unless ip_address

      timeout = host.at('//taskend/@extrainfo[contains(., "timed out")]')
      self.timed_out = !!timeout

      self.ports = []
      host.xpath('ports/port').each do |port|
        if port.at('state/@state').value == 'open'
          self.ports << port['portid']
        end
      end

    end

    self.processed = true
    self.latest = true
    # do we want to leave timed-out scan unprocessed until it's reissued?
    self.save!
  end


  def rescan!
    return if self.ports.length == 0

    # spawn a child, so each scan's results are stored.
    # If you don't have this requirement, you could reuse this object.
    self.latest = false
    self.save
    scan = self.dup
    scan.processed = false
    scan.save
    scan.enqueue!
  end

  def enqueue!
    if self.ports.length == 65536
      ports_string = '-'
      # hax
    else
      ports_string = self.ports.join(',')
    end
    Sidekiq::Client.enqueue(MultipassScannerWorker, self.id, self.ip_address.to_s, ports_string, self.options)
  end


end
