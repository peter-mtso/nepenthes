class MultipassScannerResults
  include Sidekiq::Worker
  sidekiq_options :queue => :results
  
  def perform(id, results, full)
    scan = MultipassScan.find_by_id(id)
    scan.results = results
    scan.save!
    scan.process!
  end
end
