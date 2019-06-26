require 'active_support/all'

BASE = 0x200008f8

REGS = [
  [0x00, "Magic 5A5A"],
  [0x10, "Serial number"],
  [0x17, "Firmware version"],
  [0x18, "Factory capacity"],
  [0x19, "Actual capacity (this is not charge level !)"],
  [0x1b, "Charge full cycles"],
  [0x1c, "Charge count"],
  [0x20, "Manufacture date"],
  [0x30, "Status"],
  [0x31, "Remaining capacity, mAh"],
  [0x32, "Remaining capacity, %"],
  [0x33, "Current, x10mA, positive - discharging, negative - charging"],
  [0x34, "Voltage, x10mV"],
  [0x35, "bTemperature1:bTemperature2, Deg C, 0 is -20"],
  [0x36, "Balancing bitmap"],
  [0x3b, "Health, %"],
  [0x40, "Cell 1 voltage, mV"],
  [0x41, "Cell 2 voltage, mV"],
  [0x42, "Cell 3 voltage, mV"],
  [0x43, "Cell 4 voltage, mV"],
  [0x44, "Cell 5 voltage, mV"],
  [0x45, "Cell 6 voltage, mV"],
  [0x46, "Cell 7 voltage, mV"],
  [0x47, "Cell 8 voltage, mV"],
  [0x48, "Cell 9 voltage, mV"],
  [0x49, "Cell 10 voltage, mV"],
  [0x51, "Config straps, .0 - PC5, .1 - PC6"],
  [0x70, "Activation data (MCU UID copy)"],
]

REGS.each do |offset, desc|
  name = desc.parameterize.tableize.classify
  unless name.blank?
    puts "BMS_REG_#{name} #{(BASE + (offset * 2)).to_s(16)}"
  end
end
