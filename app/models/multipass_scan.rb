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
          self.ports << port['portid'].to_i
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
    Sidekiq::Client.enqueue(MultipassScannerWorker, self.id, self.ip_address.to_s, ports_string, self.options)
  end

  # Queue a traditional scan, with version checking and all
  # This will create the Port objects when processed.
  def finalize!
    self.ip_address.queue_scan!(['-Pn', '-p', ports_string, '-sV', '--version-light'])
  end

  def ports_string
    compress self.ports
  end


  def self.compress x
    output = []
    current_base = nil
    last = nil

    out = lambda {
      if current_base == last
        output << "#{last}"
      else
        output << "#{current_base}-#{last}"
      end
    }

    x.each do |q|
      p = q.to_i
      if current_base == nil
        current_base = p
        last = p
        next
      end
      if p == last + 1
        last = p
      else
        out.()
        current_base = p
        last = p
      end
    end

    out.()
    output.join(',')
  end



end
