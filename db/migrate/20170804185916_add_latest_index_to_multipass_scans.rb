class AddLatestIndexToMultipassScans < ActiveRecord::Migration
  def change
    add_index :multipass_scans, :latest
  end
end
