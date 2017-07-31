class IpAddress < ActiveRecord::Base
  belongs_to :region
  belongs_to :tag
  has_many :scans, :dependent => :destroy
  has_many :multipass_scans, :dependent => :destroy
  has_many :ports, :dependent => :destroy
  has_many :nessus_results, :dependent => :delete_all
  attr_accessible :address, :tags
  acts_as_taggable
  store :settings, coder: JSON
  after_initialize :default_values
  
  default_scope { order(:address) }

  scope :with_ports, -> { where('ports_count > 0') }
  
  def address_and_hostname
    if self.hostname.nil? || self.hostname.empty?
      self.to_s
    else
      "#{self.to_s} (#{self.hostname})"
    end
  end
  
  def address_or_hostname
    if (self.hostname != nil) and self.hostname.empty?
      self.to_s
    else
      self.hostname
    end
  end
  
  def to_s
    NetAddr::CIDR.create(self.address.to_i).ip
  end
  
  def to_param
    to_s
  end
  
  def queue_full_scan!
    scan = self.scans.create
    
    opts = {
      "utc_start_test" => self.region.utc_start_test,
      "utc_end_test"   => self.region.utc_end_test,
      "ping_duration"  => self.ping_duration
    }
    
    Sidekiq::Client.enqueue(FullScannerWorker, scan.id, self.to_s, opts)
  end
  
  def self.find_by_dotted(dotted)
    self.find_by_address(NetAddr::CIDR.create(dotted).to_i(:ip))
  end
  
  def self.queue_full_scans!
    queued = 0

    # Will hold the options passed to the FullScannerWorker
    opts = {}

    scan = self.where(has_full_scan: false).to_a
    scan.sort! { |a,b|
      a_score = rand
      a_score += a.pingable? ? 2 : 0
      a_score += a.hostname.empty? ? 0 : 1
      a_score += a.ports.size.zero? ? 0 : 2 + a.ports.size
      b_score = rand
      b_score += b.pingable? ? 2 : 0;
      b_score += b.hostname.empty? ? 0 : 1;
      b_score += b.ports.size.zero? ? 0 : 2 + b.ports.size
      b_score <=> a_score
    }
    
    scan.each do |ip|
      scan = ip.scans.create

      opts["utc_start_test"] = ip.region.utc_start_test
      opts["utc_end_test"]   = ip.region.utc_end_test
      opts["ping_duration"]  = ip.ping_duration

      Sidekiq::Client.enqueue(FullScannerWorker, scan.id, ip.to_s, opts)
      queued += 1
    end
    
    queued
  end

  def self.queue_rescans! timeout
    queued = 0
    opts = {}
    self.where(full_scan_timed_out: true).each do |ip|
      scan = ip.scans.create
      ip.full_scan_timed_out = false
      ip.save!

      opts["utc_start_test"] = ip.region.utc_start_test
      opts["utc_end_test"]   = ip.region.utc_end_test
      opts["timeout"]        = timeout
      opts["ping_duration"]  = ip.ping_duration

      Sidekiq::Client.enqueue(FullScannerWorker, scan.id, ip.to_s, opts)
      queued += 1
    end
    # do we want to delete the old scans?
    # or repurpose them?

    queued
  end
  
  def self.queue_quick_scans!(opts = ['-Pn', '-p',
      '80,443,22,25,21,8080,23,3306,143,53', '-sV', '--version-light'])
    queued = 0
    
    while true
      ips = self.includes(:scans).where(:scans => {:ip_address_id => nil}).
        reorder('(IF(ip_addresses.hostname="", 0, 1) + '+
        'ip_addresses.pingable * 2 + '+
        'RAND()) DESC').limit(50000).to_a
      
      break if ips.length == 0
      queued += IpAddress.queue_many!(ips, opts)
    end
    
    queued
  end
  
  def queue_scan!(opts = ['-Pn', '-p', '80,443,22,25,21,8080,23,3306,143,53',
      '-sV', '--version-light'])
    # Recommend something like the above.
    unless opts.kind_of?(Array)
      throw 'opts must be an array.'
    end
    
    scan = self.scans.new(:options => opts)
    scan.save!
    Sidekiq::Client.enqueue(ScannerWorker, scan.id, self.to_s, opts)
  end

  def queue_multipass_scan!(ports = (1..65536).to_a, opts = ['-Pn', '--max-retries=2', '-v', '-sS', '-T4'])
    unless opts.kind_of?(Array)
      throw 'opts must be an array.'
    end

    scan = self.multipass_scans.new(:ports => ports, :options => opts)
    scan.save!
    scan.enqueue!
  end
  
  def self.queue_many!(ips, opts = ['-Pn', '-p',
      '80,443,22,25,21,8080,23,3306,143,53', '-sV', '--version-light'])
    opts_str = self.connection.quote(opts.to_yaml)
    
    sql_prefix = "INSERT INTO `scans` (`created_at`, `updated_at`, "+
      "`options`, `ip_address_id`) VALUES "
    val_prefix = "(NOW(), NOW(), #{opts_str}, "
    val_suffix = ")"
    sql_parts = []
    ips.each do |ip|
      sql_parts << val_prefix + ip.id.to_s + val_suffix
    end
    first_id = self.connection.insert(sql_prefix + sql_parts.join(', '))
    
    scan_id = first_id
    ips.each do |ip|
      Sidekiq::Client.enqueue(ScannerWorker, scan_id, ip.to_s, opts)
      scan_id += 1
    end
    
    ips.length
  end
  
  def self.not_hostname_checked
    self.where(hostname: nil)
  end
  
  def self.queue_hostname_checks!
    queued = 0
    self.not_hostname_checked.each do |ip|
      ip.queue_check_hostname!
      queued += 1
    end
    
    queued
  end
  
  def queue_check_hostname!
    Sidekiq::Client.enqueue(HostnameWorker, [[self.id, self.to_s]])
  end
  
  def self.pingable
    self.where(pingable: true)
  end
  
  def self.not_pinged
    self.where(pinged: false)
  end
  
  def self.queue_pings!
    queued = 0
    self.not_pinged.each do |ip|
      ip.queue_ping!
      queued += 1
    end
    
    queued
  end
  
  def queue_ping!
    Sidekiq::Client.enqueue(PingWorker, self.id, self.to_s)
  end

  def has_port x
    self.ports.where(number: x).any?
  end

  def port_numbers
    self.ports.map(&:number).sort
  end

  def self.to_csv port_columns
    port_columns ||= Port::COMMON_PORTS
    CSV.generate do |csv|
      columns = ['host'] + port_columns + ['other']
      csv << columns
      IpAddress.with_ports.each do |addr|
        ports = addr.port_numbers
        commons = port_columns.map {|x| 'X' if ports.include? x}
        others = (ports - port_columns).join ', '
        row = [addr.address_and_hostname] + commons + [others]
        csv << row
      end
    end
  end

private
  def default_values
    self.rand ||= rand
  end
end
