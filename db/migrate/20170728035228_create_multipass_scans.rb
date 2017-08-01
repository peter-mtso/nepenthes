class CreateMultipassScans < ActiveRecord::Migration
  def change
    create_table :multipass_scans do |t|
      t.integer :ip_address_id
      t.text :ports, limit: 16777215
      t.text :results, limit: 2147483647
      t.text :options
      t.boolean :processed, default: false, null: false
      t.boolean :timed_out
      t.boolean :latest

      t.timestamps null: false
    end
    add_index :multipass_scans, :ip_address_id
  end
end
