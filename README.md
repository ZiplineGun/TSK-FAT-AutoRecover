# TSK-FAT-AutoRecover
A wrapper tool for FAT extraction and recovery using [The Sleuth Kit](https://www.sleuthkit.org/).
> The Sleuth Kit® is a collection of command line tools and a C library that allows you to analyze disk images and recover files from them.

## Features
- Scans all sectors in a disk image to detect FAT BPBs.
- Then passes the detected offsets to `tsk_recover`, a file system recovery tool included in the The Sleuth Kit, to extract files.
- Supported filesystems: FAT12/16/32, exFAT
- To better detect non-standard FAT BPBs:
  - The initial 3-byte bootstrap code is ignored during detection.
  - The tool prioritizes the `BS_FilSysType` field over `CountOfClusters` when determining the FAT type.
  - An option is available to ignore the 0xAA55 signature at the end of the BPB.
- Backup BPBs in FAT32 and exFAT are skipped.


## Usage Examples
Help: `python extract_fat.py -h`

- Extract and recover files from an image file:
  - `python extract_fat.py image.bin`
- Carve out the region from one FAT BPB to the next and save it as a separate file
(useful when using other FAT extraction tools):
  - `python extract_fat.py --carve-fat --no-extract-fat image.bin`
- Only view FAT BPB information without carving or extracting:
  - `python extract_fat.py --no-carve-fat --no-extract-fat image.bin`
 
## Installation

### Windows
Download the appropriate Sleuth Kit (`***-win32.zip`) from:

https://github.com/sleuthkit/sleuthkit/releases

Then extract it to a directory of your choice.

Set the `sleuthkit_path` value in `extract_fat.ini` to the `bin` folder inside the extracted Sleuth Kit directory.  
Alternatively, if the path is included in your system's `PATH` environment variable, it will be used automatically.

### Linux
Install Sleuth Kit with:
`sudo apt install sleuthkit`

No changes to `extract_fat.ini` are required.
