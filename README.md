# esp-idf-defs

Python data structures for ESP-IDF internals — partition tables, firmware image headers, OTA data, and application descriptors.

Used by [`idftool`](https://github.com/nebkat/idftool).

## Installation

```bash
pip install esp-idf-defs
```

## Classes

### Partition table

```python
from esp_idf_defs import PartitionTable, PartitionDefinition

table = PartitionTable.from_binary(data)   # parse binary partition table
table = PartitionTable.from_csv(text)      # parse CSV partition table

partition = table["ota_0"]                 # look up by name
print(partition.offset, partition.size)
```

### Firmware images

```python
from esp_idf_defs import ImageMetadata

image = ImageMetadata.from_binary(data)
print(image.header.chip_id, image.app_description.version)
```

### OTA data

```python
from esp_idf_defs import OtaDataSelectEntry
from esp_idf_defs.otadata import OtaDataParameters

entry = OtaDataSelectEntry.from_binary(data)
print(entry.ota_seq, entry.state)
```

### Application descriptor

```python
from esp_idf_defs import AppDescription

desc = AppDescription.from_binary(data)
print(desc.project_name, desc.version)
```
