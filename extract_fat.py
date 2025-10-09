import argparse
import struct
import os
import subprocess
import configparser
import sys
import shutil
import mmap

def main(input_path, output_dir, enable_check_fat_signature, enable_carve_fat, enable_extract_fat, enable_recover_files, detection_step, config_path):
    print("Start detecting and analyzing FAT BPB.")
    bpb_offs = detect_bpb_offset_mmap(input_path, enable_check_fat_signature, detection_step)
    fat_infos = get_fat_infos(input_path, bpb_offs)
    fat_infos = remove_backup_sector(fat_infos)

    if enable_carve_fat and len(fat_infos) > 0:
        print("\nStart carving FAT.")
        carve_fat(input_path, fat_infos, output_dir)
    
    if enable_extract_fat and len(fat_infos) > 0:
        print("\nStart extracting FAT.")
        exe_name = get_exe_path(config_path)
        os.makedirs(output_dir, exist_ok=True)

        for i, fat_info in enumerate(fat_infos):
            extraction_name = f'{i:02X}_FAT_0x{fat_info["bpb_off"]:09X}_extracted'
            print(f"\n[{extraction_name}]")

            extract_fat(
                input_path,
                os.path.join(output_dir, extraction_name),
                exe_name,
                fat_info,
                enable_recover_files
            )

    if enable_carve_fat or enable_extract_fat:
        print(f"\nOutput => {output_dir}")
    else:
        print("End")


def get_fat_infos(input_path, bpb_offs):
    fat_infos = []
    
    with open(input_path, "rb") as inf:
        for bpb_off in bpb_offs:
            inf.seek(bpb_off)
            bpb_data = inf.read(0x200)
            common_bpb_info = parse_common_bpb(bpb_data)

            is_exfat = bpb_is_exfat(bpb_data)

            if is_exfat:
                additional_bpb_info = parse_exfat_bpb(bpb_data)
            elif common_bpb_info["BPB_FATSz16"] == 0:
                additional_bpb_info = parse_fat32_bpb(bpb_data)
            else:
                additional_bpb_info = parse_fat12_16_bpb(bpb_data)

            bpb_info = common_bpb_info | additional_bpb_info

            fat_type_by_countofclusters = None if is_exfat else detect_fat_type_by_countofclusters(bpb_info)

            fat_type_by_filsystype = None if is_exfat else detect_fat_type_by_filsystype(bpb_info)

            fat_infos.append({
                "bpb_off": bpb_off,
                "bpb_info": bpb_info,
                "fat_type_by_filsystype": fat_type_by_filsystype,
                "fat_type_by_countofclusters": fat_type_by_countofclusters,
                "fat_type": "exfat" if is_exfat else (fat_type_by_filsystype or fat_type_by_countofclusters),
            })

        for fat_info in fat_infos:
            print(f'\n{hex(fat_info["bpb_off"])} ({fat_info["fat_type"]}) (fat_type_by_countofclusters: {fat_info["fat_type_by_countofclusters"]}, fat_type_by_filsystype: {fat_info["fat_type_by_filsystype"]}): ')
            print(fat_info["bpb_info"])
        print("")

        return fat_infos


def resolve_path(path, base_dir):
    if os.path.isabs(path):
        return os.path.normpath(path)
    else:
        return os.path.normpath(os.path.join(base_dir, path))


def get_exe_path(config_path):
    # Windows
    if os.name == "nt":
        config = configparser.ConfigParser()
        config.read(config_path)

        exe_from_ini = None
        if config.has_section("settings") and config.has_option("settings", "sleuthkit_path"):
            sleuthkit_path = resolve_path(config["settings"]["sleuthkit_path"], os.path.dirname(config_path))

            if sleuthkit_path:
                candidate = os.path.join(sleuthkit_path, "tsk_recover.exe")
                if os.path.isfile(candidate):
                    return candidate
                exe_from_ini = candidate

        exe_from_path = shutil.which("tsk_recover.exe")
        if exe_from_path:
            return exe_from_path

        if exe_from_ini:
            raise FileNotFoundError(f"tsk_recover.exe not found at path from ini: {exe_from_ini}")
        else:
            raise FileNotFoundError(
                "tsk_recover.exe was not found. Set 'sleuthkit_path' in the ini or install SleuthKit and ensure tsk_recover.exe is on PATH."
            )

    # POSIX: PATH lookup is usually enough
    elif os.name == "posix":
        exe_from_path = shutil.which("tsk_recover")
        if exe_from_path:
            return exe_from_path

        # Optional: if you want a helpful hint rather than just 'not found'
        raise FileNotFoundError(
            "tsk_recover not found on PATH. Install sleuthkit (e.g. `sudo apt install sleuthkit`) "
            "or place tsk_recover on PATH, or configure a path in an ini and adjust get_exe_name to read it."
        )

    else:
        raise RuntimeError(f"Unsupported OS: {os.name}")
    

def is_ascii_or_00(data):
    for b in data:
        if not (b == 0 or 0x20 <= b <= 0x7E):
            return False
    return True


def remove_backup_sector(fat_infos):
    backup_sector_offs = {
        off for off in (
            get_backup_sector_off(fi["fat_type"], fi["bpb_info"], fi["bpb_off"])
            for fi in fat_infos
        ) if off is not None
    }
    new_fat_infos = []

    for i, fat_info in enumerate(fat_infos):
        if fat_info["bpb_off"] in backup_sector_offs:
            print(f"Skip {i} BPB due to backup boot sector.")
            continue
        new_fat_infos.append(fat_info)

    return new_fat_infos


def get_backup_sector_off(fat_type, bpb_info, bpb_off):
    if fat_type == "fat32" and bpb_info["BPB_BkBootSec"] != 0 :
        return bpb_off + bpb_info["BPB_BkBootSec"] * bpb_info["BPB_BytsPerSec"]
    elif fat_type == "exfat":
        bytes_per_sector = 1 << bpb_info["BytesPerSectorShift"]
        return bpb_off + 12 * bytes_per_sector
    else:
        return None


def bpb_is_exfat(boot_sector):
    if (boot_sector[0x3 : 0xB] == b"EXFAT   " and
        boot_sector[0xB : 0x40] == b"\x00" * 0x35
    ):
        return True
    
    return False
    

def detect_fat_type_by_countofclusters(bpb_info):
    needed = ("BPB_RootEntCnt", "BPB_BytsPerSec", "BPB_SecPerClus", "BPB_RsvdSecCnt", "BPB_NumFATs", "BPB_FATSz16", "BPB_TotSec16", "BPB_TotSec32")
    if any(k not in bpb_info for k in needed):
        return None

    FatStartSector = bpb_info["BPB_RsvdSecCnt"]
    BPB_FATSz = bpb_info["BPB_FATSz32"] if bpb_info["BPB_FATSz16"] == 0 else bpb_info["BPB_FATSz16"]
    FatSectors = BPB_FATSz * bpb_info["BPB_NumFATs"]
    RootDirStartSector = FatStartSector + FatSectors

    RootDirSectors = (bpb_info["BPB_RootEntCnt"] * 32 + bpb_info["BPB_BytsPerSec"] - 1) // bpb_info["BPB_BytsPerSec"]

    DataStartSector = RootDirStartSector + RootDirSectors
    BPB_TotSec = bpb_info["BPB_TotSec32"] if bpb_info["BPB_TotSec16"] == 0 else bpb_info["BPB_TotSec16"]
    DataSectors = BPB_TotSec - DataStartSector;
    CountofClusters = DataSectors // bpb_info["BPB_SecPerClus"]

    # Lowercase for sleuthkit.
    if CountofClusters < 4085:
        return "fat12"
    elif CountofClusters < 65525:
        return "fat16"
    else:
        return "fat32"


def detect_fat_type_by_filsystype(bpb_info):
    if "BS_FilSysType" not in bpb_info:
        return None

    if bpb_info["BS_FilSysType"].startswith("FAT12"):
        return "fat12"
    elif bpb_info["BS_FilSysType"].startswith("FAT16"):
        return "fat16"
    elif bpb_info["BS_FilSysType"].startswith("FAT32"):
        return "fat32"
    
    return None


def parse_common_bpb(boot_sector: bytes):
    if len(boot_sector) != 0x200:
        raise ValueError("Boot sector must be exactly 512 (0x200) bytes.")

    BS_jmpBoot     = boot_sector[0:3]
    BS_OEMName     = boot_sector[3:11].decode('ascii', errors='replace').rstrip()
    BPB_BytsPerSec = struct.unpack_from("<H", boot_sector, 11)[0]
    BPB_SecPerClus = struct.unpack_from("<B", boot_sector, 13)[0]
    BPB_RsvdSecCnt = struct.unpack_from("<H", boot_sector, 14)[0]
    BPB_NumFATs    = struct.unpack_from("<B", boot_sector, 16)[0]
    BPB_RootEntCnt = struct.unpack_from("<H", boot_sector, 17)[0]
    BPB_TotSec16   = struct.unpack_from("<H", boot_sector, 19)[0]
    BPB_Media      = struct.unpack_from("<B", boot_sector, 21)[0]
    BPB_FATSz16    = struct.unpack_from("<H", boot_sector, 22)[0]
    BPB_SecPerTrk  = struct.unpack_from("<H", boot_sector, 24)[0]
    BPB_NumHeads   = struct.unpack_from("<H", boot_sector, 26)[0]
    BPB_HiddSec    = struct.unpack_from("<I", boot_sector, 28)[0]
    BPB_TotSec32   = struct.unpack_from("<I", boot_sector, 32)[0]

    return {
        "BS_jmpBoot": BS_jmpBoot,
        "BS_OEMName": BS_OEMName,
        "BPB_BytsPerSec": BPB_BytsPerSec,
        "BPB_SecPerClus": BPB_SecPerClus,
        "BPB_RsvdSecCnt": BPB_RsvdSecCnt,
        "BPB_NumFATs": BPB_NumFATs,
        "BPB_RootEntCnt": BPB_RootEntCnt,
        "BPB_TotSec16": BPB_TotSec16,
        "BPB_Media": BPB_Media,
        "BPB_FATSz16": BPB_FATSz16,
        "BPB_SecPerTrk": BPB_SecPerTrk,
        "BPB_NumHeads": BPB_NumHeads,
        "BPB_HiddSec": BPB_HiddSec,
        "BPB_TotSec32": BPB_TotSec32,
    }


def parse_fat12_16_bpb(boot_sector: bytes):
    if len(boot_sector) != 0x200:
        raise ValueError("Boot sector must be exactly 512 (0x200) bytes.")

    BS_DrvNum      = struct.unpack_from("<B", boot_sector, 36)[0]
    BS_Reserved1   = struct.unpack_from("<B", boot_sector, 37)[0]
    BS_BootSig     = struct.unpack_from("<B", boot_sector, 38)[0]
    BS_VolID       = struct.unpack_from("<I", boot_sector, 39)[0]
    BS_VolLab      = boot_sector[43:54].decode("ascii", errors="replace").rstrip()
    BS_FilSysType  = boot_sector[54:62].decode("ascii", errors="replace").rstrip()

    return {
        "BS_DrvNum": BS_DrvNum,
        "BS_Reserved1": BS_Reserved1,
        "BS_BootSig": BS_BootSig,
        "BS_VolID": BS_VolID,
        "BS_VolLab": BS_VolLab,
        "BS_FilSysType": BS_FilSysType,
    }


def parse_fat32_bpb(boot_sector: bytes):
    if len(boot_sector) != 0x200:
        raise ValueError("Boot sector must be exactly 512 (0x200) bytes.")

    BPB_FATSz32    = struct.unpack_from("<I", boot_sector, 36)[0]
    BPB_ExtFlags   = struct.unpack_from("<H", boot_sector, 40)[0]
    BPB_FSVer      = struct.unpack_from("<H", boot_sector, 42)[0]
    BPB_RootClus   = struct.unpack_from("<I", boot_sector, 44)[0]
    BPB_FSInfo     = struct.unpack_from("<H", boot_sector, 48)[0]
    BPB_BkBootSec  = struct.unpack_from("<H", boot_sector, 50)[0]
    BPB_Reserved   = boot_sector[52:64]

    BS_DrvNum      = struct.unpack_from("<B", boot_sector, 64)[0]
    BS_Reserved1   = struct.unpack_from("<B", boot_sector, 65)[0]
    BS_BootSig     = struct.unpack_from("<B", boot_sector, 66)[0]
    BS_VolID       = struct.unpack_from("<I", boot_sector, 67)[0]
    BS_VolLab      = boot_sector[71:82].decode("ascii", errors="replace").rstrip()
    BS_FilSysType  = boot_sector[82:90].decode("ascii", errors="replace").rstrip()

    return {
        "BPB_FATSz32": BPB_FATSz32,
        "BPB_ExtFlags": BPB_ExtFlags,
        "BPB_FSVer": BPB_FSVer,
        "BPB_RootClus": BPB_RootClus,
        "BPB_FSInfo": BPB_FSInfo,
        "BPB_BkBootSec": BPB_BkBootSec,
        "BPB_Reserved": BPB_Reserved,
        "BS_DrvNum": BS_DrvNum,
        "BS_Reserved1": BS_Reserved1,
        "BS_BootSig": BS_BootSig,
        "BS_VolID": BS_VolID,
        "BS_VolLab": BS_VolLab,
        "BS_FilSysType": BS_FilSysType,
    }


def parse_exfat_bpb(boot_sector: bytes):
    if len(boot_sector) < 512:
        raise ValueError("Boot sector must be at least 512 bytes.")

    JumpBoot                  = boot_sector[0:3]
    FileSystemName            = boot_sector[3:11].decode('ascii', errors='replace').rstrip()
    MustBeZero                = boot_sector[11:64]
    PartitionOffset           = struct.unpack_from("<Q", boot_sector, 64)[0]
    VolumeLength              = struct.unpack_from("<Q", boot_sector, 72)[0]
    FatOffset                 = struct.unpack_from("<I", boot_sector, 80)[0]
    FatLength                 = struct.unpack_from("<I", boot_sector, 84)[0]
    ClusterHeapOffset         = struct.unpack_from("<I", boot_sector, 88)[0]
    ClusterCount              = struct.unpack_from("<I", boot_sector, 92)[0]
    FirstClusterOfRootDir     = struct.unpack_from("<I", boot_sector, 96)[0]
    VolumeSerialNumber        = struct.unpack_from("<I", boot_sector, 100)[0]
    FileSystemRevision        = struct.unpack_from("<H", boot_sector, 104)[0]
    VolumeFlags               = struct.unpack_from("<H", boot_sector, 106)[0]
    BytesPerSectorShift       = boot_sector[108]
    SectorsPerClusterShift    = boot_sector[109]
    NumberOfFats              = boot_sector[110]
    DriveSelect               = boot_sector[111]
    PercentInUse              = boot_sector[112]
    Reserved                  = boot_sector[113:120] 
    BootCode                  = boot_sector[120:510]
    BootSignature             = struct.unpack_from("<H", boot_sector, 510)[0]
    ExcessSpace = boot_sector[512:] if len(boot_sector) > 512 else b''

    return {
        "JumpBoot": JumpBoot,
        "FileSystemName": FileSystemName,
        "MustBeZero": MustBeZero,
        "PartitionOffset": PartitionOffset,
        "VolumeLength": VolumeLength,
        "FatOffset": FatOffset,
        "FatLength": FatLength,
        "ClusterHeapOffset": ClusterHeapOffset,
        "ClusterCount": ClusterCount,
        "FirstClusterOfRootDir": FirstClusterOfRootDir,
        "VolumeSerialNumber": VolumeSerialNumber,
        "FileSystemRevision": FileSystemRevision,
        "VolumeFlags": VolumeFlags,
        "BytesPerSectorShift": BytesPerSectorShift,
        "SectorsPerClusterShift": SectorsPerClusterShift,
        "NumberOfFats": NumberOfFats,
        "DriveSelect": DriveSelect,
        "PercentInUse": PercentInUse,
        "Reserved": Reserved,
        "BootCode": BootCode,
        "BootSignature": BootSignature,
        "ExcessSpace": ExcessSpace,
    }

    
def detect_bpb_offset_mmap(input_path, enable_check_fat_signature, detection_step):
    if detection_step <= 0:
        raise ValueError("The detection_step is an invalid value.")
    
    dump_size = os.path.getsize(input_path)
    if dump_size < 0x200:
        return []

    exfat_sig = b"EXFAT   "
    zero35 = b"\x00" * 0x35
    valid_bytes_per_sec = frozenset((512, 1024, 2048, 4096))
    valid_sec_per_clust = frozenset((1,2,4,8,16,32,64,128))

    bpb_offs = []
    with open(input_path, "rb") as inf, mmap.mmap(inf.fileno(), 0, access=mmap.ACCESS_READ) as dump_mm:
        max_offset = dump_size - 0x200
        unpack_u16 = lambda off: struct.unpack_from("<H", dump_mm, off)[0]

        for offset in range(0, max_offset + 1, detection_step):
            # Signature
            if enable_check_fat_signature and not (dump_mm[offset+0x1FE] == 0x55 and dump_mm[offset+0x1FF] == 0xAA):
                continue

            # exFAT
            if (dump_mm[offset + 0x3 : offset + 0xB] == exfat_sig and
                dump_mm[offset + 0xB : offset + 0x40] == zero35
            ):
                bpb_offs.append(offset)
                continue

            # FAT12/16/32
            # OEM Name
            oem = dump_mm[offset+3:offset+0xB]
            if is_ascii_or_00(oem): 
                # BytesPerSec
                if unpack_u16(offset + 0xB) not in valid_bytes_per_sec:
                    continue

                # SecPerClus
                if dump_mm[offset + 0xD] not in valid_sec_per_clust:
                    continue
            
                # RsvdSecCnt
                if unpack_u16(offset + 0xE) == 0:
                    continue
            
                bpb_offs.append(offset)
    return bpb_offs


def carve_fat(input_path, fat_infos, output_dir):
    filenames = []
        
    os.makedirs(output_dir, exist_ok=True)
    with open(input_path, "rb") as inf:
        for i, fat_info in enumerate(fat_infos):
            filename = f'{i:02X}_FAT_0x{fat_info["bpb_off"]:09X}.img'
            start = fat_info["bpb_off"]

            # End
            if i == (len(fat_infos) - 1):
                size = os.path.getsize(input_path) - start
            else:
                size = fat_infos[i+1]["bpb_off"] - start

            with open(os.path.join(output_dir, filename), "wb") as outf:
                inf.seek(start)
                outf.write(inf.read(size))

            filenames.append(filename)
        
    return filenames


def extract_fat(input, output_dir, exe_name, fat_info, enable_recover_files):
    bytes_per_sector = (
        1 << fat_info["bpb_info"]["BytesPerSectorShift"]
        if "BytesPerSectorShift" in fat_info["bpb_info"]
        else fat_info["bpb_info"]["BPB_BytsPerSec"]
    )

    command = []
    command.append(exe_name)
    if enable_recover_files: command.append("-e")
    command.extend(["-f", fat_info["fat_type"]])
    command.extend(["-o", str(fat_info["bpb_off"] // bytes_per_sector)]) # sector offset
    command.extend(["-b", str(bytes_per_sector)])
    command.append(input)
    command.append(output_dir)

    subprocess.run(command)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="FAT extraction tool using sleuthkit.")
    parser.add_argument("input")
    parser.add_argument("-o", "--output", default=None, help="Default: In the same folder as the input file.")
    parser.add_argument("-s", "--check-fat-signature", action=argparse.BooleanOptionalAction, default=True,
                        help="Check for the 0xAA55 signature at the end of the BPB during detection. Default: %(default)s")
    parser.add_argument("-c", "--carve-fat", action=argparse.BooleanOptionalAction, default=False,
                        help="Save the detected FAT region as a separate file. Default: %(default)s")
    parser.add_argument("-e", "--extract-fat", action=argparse.BooleanOptionalAction, default=True,
                        help="Enable file extraction from the FAT filesystem. Default: %(default)s")
    parser.add_argument("-r", "--recover-files", action=argparse.BooleanOptionalAction, default=True,
                        help="Enable recovery of deleted files during extraction. Default: %(default)s")
    parser.add_argument("-d", "--detection-step", type=lambda x: int(x, 0), default=0x200,
                        help=f"Number of bytes between detection steps. Integer value (decimal or hex like 0x100). Default: %(default)s")

    args = parser.parse_args()

    output_dir = os.path.join(os.path.dirname(args.input), f"{os.path.splitext(os.path.basename(args.input))[0]}_FAT") if args.output is None else args.output

    config_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "extract_fat.ini")

    main(args.input, output_dir, args.check_fat_signature, args.carve_fat, args.extract_fat, args.recover_files, args.detection_step, config_path)
