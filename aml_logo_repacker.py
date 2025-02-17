from __future__ import annotations
import struct
import argparse
import binascii
import os
import gzip
import io
import json
import sys
from pathlib import Path

AML_RES_IMG_VERSION_V1 = 0x01
AML_RES_IMG_VERSION_V2 = 0x02
AML_RES_IMG_ITEM_ALIGN_SZ = 16
AML_RES_IMG_VERSION = 0x01
AML_RES_IMG_V1_MAGIC_LEN = 8
AML_RES_IMG_V1_MAGIC = b'AML_RES!' # 8 chars
AML_RES_IMG_HEAD_SZ = AML_RES_IMG_ITEM_ALIGN_SZ * 4 # 64
AML_RES_ITEM_HEAD_SZ = AML_RES_IMG_ITEM_ALIGN_SZ * 4 # 64
IH_MAGIC = 0x27051956 # Image Magic Number
IH_NMLEN = 32 # Image Name Length
ARCH_ARM = 8


# typedef struct {
#     __u32   crc;    //crc32 value for the resouces image
#     __s32   version;//current version is 0x01
#     __u8    magic[AML_RES_IMG_V1_MAGIC_LEN];  //resources images magic
#     __u32   imgSz;  //total image size in byte
#     __u32   imgItemNum;//total item packed in the image
#     __u32   alignSz;//AML_RES_IMG_ITEM_ALIGN_SZ
#     __u8    reserv[AML_RES_IMG_HEAD_SZ - 8 * 3 - 4];
# }AmlResImgHead_t;

# typedef struct pack_header{
#     unsigned int    magic;  /* Image Header Magic Number    */
#     unsigned int    hcrc;   /* Image Header CRC Checksum    */
#     unsigned int    size;   /* Image Data Size      */
#     unsigned int    start;  /* item data offset in the image*/
#     unsigned int    end;    /* Entry Point Address      */
#     unsigned int    next;   /* Next item head offset in the image*/
#     unsigned int    dcrc;   /* Image Data CRC Checksum  */
#     unsigned char   index;  /* Operating System     */
#     unsigned char   nums;   /* CPU architecture     */
#     unsigned char   type;   /* Image Type           */
#     unsigned char   comp;   /* Compression Type     */
#     char    name[IH_NMLEN]; /* Image Name       */
# }AmlResItemHead_t;

def align_data(data: bytes, alignment: int = 16, fill_byte: int = 0x00) -> bytes:
    padding = (alignment - (len(data) % alignment)) % alignment
    return data + bytearray([fill_byte] * padding)

def is_bmp(data: bytes) -> bool:
    """Проверяет, является ли файл BMP по сигнатуре."""
    return len(data) >= 2 and data[:2] == b'BM'


def get_bmp_info(data: bytes):
    """Анализирует BMP-файл и извлекает информацию."""
    header = data[:54]  # Заголовок BMP (54 байта)
    file_size = struct.unpack("<I", header[2:6])[0]
    width = struct.unpack("<I", header[18:22])[0]
    height = struct.unpack("<I", header[22:26])[0]
    bit_depth = struct.unpack("<H", header[28:30])[0]
    compression = struct.unpack("<I", header[30:34])[0]
  # Читаем цветовые маски, если битность 16 или 32
    color_masks = {}
    if bit_depth in (16, 32):
        masks = struct.unpack_from("<III", data, 54)
        color_masks = {
        "red_mask": hex(masks[0]),
        "green_mask": hex(masks[1]),
        "blue_mask": hex(masks[2])
        }
    return {
        "file_size": file_size,
        "width": width,
        "height": height,
        "bit_depth": bit_depth,
        "compression": compression,
        "color_masks": color_masks
    }

def save_to_json(data, output_file):
    """Сохраняет список данных в JSON-файл."""
    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=4, ensure_ascii=False)

def load_json(json_file):
    """Загружает JSON-файл"""
    if not os.path.exists(json_file):
        print(f"Файл {json_file} не найден!")
        return

    with open(json_file, encoding="utf-8") as f:
        data = json.load(f)
    return data

# Переместить элемент словаря в начало
def move_to_start(d, key):
    if key in d:
        value = d.pop(key)  # Удаляем ключ и получаем его значение
        return {key: value, **d}  # Создаём новый словарь с нужным порядком
    return d  # Если ключа нет, возвращаем без изменений

class AmlResourcesImage(object):
    def __init__(self):
        self.header = AmlResImgHead()
        self.items = []

    @classmethod
    def unpack_from(cls, fp) -> AmlResourcesImage:
        img = cls()
        fp.seek(0)
        img.header = AmlResImgHead.unpack_from(fp)
        while True:
            item = AmlResItem.unpack_from(fp)
            img.items.append(item)
            if item.next == 0:
                break
            fp.seek(item.next)
        return img

    def pack(self) -> bytes:
        packed = bytes()

        data_pack = bytes()
        for item in self.items:
            item.start = len(data_pack) + AmlResImgHead._size + (AmlResItem._size * len(self.items))
            data_pack += item.data
            data_pack += struct.pack("%ds" % (len(data_pack) % self.header.alignSz), b"\0" * self.header.alignSz)

        for i, item in enumerate(self.items):
            item.index = i
            if i < (len(self.items) - 1):
                item.next = AmlResImgHead._size + (AmlResItem._size * (i + 1))
            packed += item.pack()
        self.header.imgItemNum = len(self.items)
        self.header.imgSz = AmlResImgHead._size + len(packed) + len(data_pack)
        self.header.crc = binascii.crc32(data_pack) & 0xFFFFFFFF
        full_data = self.header.pack() + packed + data_pack
        return full_data


class AmlResItem:
    _format = "IIIIIIIBBBB%ds" % IH_NMLEN
    _size = struct.calcsize(_format)
    magic = IH_MAGIC
    hcrc = 0
    size = 0
    start = 0
    end = 0
    next = 0
    dcrc = 0
    index = 0
    nums = ARCH_ARM
    type = 0
    comp = 0
    name = ""
    data = bytes()

    def to_dict(self):
        return self.__dict__

    @classmethod
    def from_file(cls, file: Path, index, config) -> AmlResItem:
        item = cls()
        with open(file, mode='br') as fp:
            file_data = fp.read()
        for config_item in config:
            if (config_item['name'] == file.stem):
                if (config_item['format'] =='gz'):
                    file_data = gzip.compress(file_data, compresslevel=6)
        item.size = len(file_data)
        item.data = align_data(file_data)
        item.name = file.stem
        item.index = index # порядковый номер
        return item

    @classmethod
    def unpack_from(cls, fp) -> AmlResItem:
        h = cls()
        h.magic, h.hcrc, h.size, h.start, h.end, h.next, h.dcrc, h.index, \
        h.nums, h.type, h.comp, h.name = struct.unpack(h._format, fp.read(h._size))
        h.name = h.name.rstrip(b'\0')
        if h.magic != IH_MAGIC:
            raise Exception("Invalid item header magic, should 0x%x, is 0x%x" % (IH_MAGIC, h.magic))
        fp.seek(h.start)
        h.data = fp.read(h.size)
        return h

    def pack(self) -> bytes:
        packed = struct.pack(self._format, self.magic, self.hcrc, self.size, self.start, self.end, self.next, self.dcrc, self.index, self.nums,self.type, self.comp, self.name.encode('utf-8'))
        return packed

    def __repr__(self) -> str:
        return "AmlResItem(name=%s start=0x%x size=%d)" % (self.name, self.start, self.size)


class AmlResImgHead(object):
    _format = "Ii%dsIII%ds" % (AML_RES_IMG_V1_MAGIC_LEN, AML_RES_IMG_HEAD_SZ - 8 * 3 - 4)
    _size = struct.calcsize(_format)
    crc = 0
    version = AML_RES_IMG_VERSION_V2
    magic = AML_RES_IMG_V1_MAGIC
    imgSz = 0
    imgItemNum = 0
    alignSz = AML_RES_IMG_ITEM_ALIGN_SZ
    reserv = ""

    @classmethod
    def unpack_from(cls, fp) -> AmlResImgHead:
        h = cls()
        h.crc, h.version, h.magic, h.imgSz, h.imgItemNum, h.alignSz, h.reserv = struct.unpack(h._format, fp.read(h._size))
        if h.magic != AML_RES_IMG_V1_MAGIC:
            raise Exception("Magic is not right, should %s, is %s" % (AML_RES_IMG_V1_MAGIC, h.magic))
        if h.version > AML_RES_IMG_VERSION_V2:
            raise Exception("res-img version %d not supported" % h.version)
        return h

    def pack(self) -> bytes:
        packed = struct.pack(self._format, self.crc, self.version, self.magic, self.imgSz, self.imgItemNum, self.alignSz, self.reserv.encode('utf-8'))
        return packed

    def __repr__(self) -> str:
        return "AmlResImgHead(crc=0x%x version=%d imgSz=%d imgItemNum=%d alignSz=%d)" % \
            (self.crc, self.version, self.imgSz, self.imgItemNum, self.alignSz)



def list_items(logo_img_file):
    print("Listing assets in %s" % logo_img_file)
    with open(logo_img_file, mode='rb') as fp:
        img = AmlResourcesImage.unpack_from(fp)
        print(img.header)
        for item in img.items:
            print("    %s" % item)

def is_valid_gzip(data: bytes) -> bool:
    if data[:2] != b'\x1f\x8b':  # Проверка сигнатуры GZIP
        return False
    try:
        with gzip.GzipFile(fileobj=io.BytesIO(data)) as f:
            f.read(1)  # Попытка прочитать хотя бы один байт
        return True
    except gzip.BadGzipFile:
        return False

def get_gzip_compression_level_from_bytes(gz_bytes):
    if len(gz_bytes) < 10:
        raise ValueError("Недостаточно данных для заголовка GZIP")
    compression_flag = gz_bytes[8]  # 9-й байт заголовка (индексация с 0)
    return int(hex(compression_flag),16)

def decompress_gzip(data: bytes) -> bytes:
    with gzip.GzipFile(fileobj=io.BytesIO(data)) as f:
        return f.read()  # Распаковка в новый массив байт

def unpack_image_file(logo_img_file, output_dir, config_file):
    print("Unpacking assets in %s" % logo_img_file)
    bmp_info_list = []
    with open(logo_img_file, mode='rb') as fp:
        img = AmlResourcesImage.unpack_from(fp)
        for item in img.items:
            name=item.name.decode('utf-8')
            print("  Unpacking %s" % name)
            data=item.data
            file_info=item.to_dict()
            del file_info['data']
            file_info['name']=name
            file_info['format'] = 'bmp'
            if(is_valid_gzip(data)):
                compress_level=get_gzip_compression_level_from_bytes(data)
                data=decompress_gzip(data)
                file_info['format'] = 'gz'
                file_info['gz_compress'] = compress_level
            file_name=os.path.join(output_dir,name)
            bmp_info=dict()
            if data[:2] == b'BM':
                bmp_info=get_bmp_info(data)
            else:
                bmp_info.clear()
            full_info_file=file_info | bmp_info
            full_info_file=move_to_start(full_info_file, 'name')
            bmp_info_list.append(full_info_file)
            with open("%s.bmp" % file_name, "wb") as item_fp:
                item_fp.write(data)
    save_to_json(bmp_info_list, config_file)

def pack_image_file(outfile, assets, config):
    print("Packing files in %s:" % outfile)
    img = AmlResourcesImage()
    img.items = []
    for i, asset in enumerate(assets):
        path=Path(asset)
        amlresitem=AmlResItem.from_file(path, i, config)
        img.items.append(amlresitem)
    for item in img.items:
        print("  %s (%d bytes)" % (item.name, item.size))
    with open(outfile, "wb") as fp:
        data=img.pack()
        fp.write(data)

def main():
    parser = argparse.ArgumentParser(description="Pack and unpack Amlogic uboot images")
    parser.add_argument("--unpack", help="Unpack image file", action="store_true")
    parser.add_argument("--pack", help="Pack image file")
    parser.add_argument("--output", help="Output directory (optional)")
    parser.add_argument("assets", metavar="file", type=str, nargs="+", help="Input file(s)/folder")

    args = parser.parse_args()

    # Преобразуем путь к абсолютному
    input_file = os.path.abspath(args.assets[0])
    config_file=""

    if args.unpack:
        # Определяем выходную папку
        if args.output:
            output_dir = os.path.abspath(args.output)  # Преобразуем в абсолютный путь
        else:
            input_dir = os.path.dirname(input_file)  # Папка, где лежит входной файл
            input_name = os.path.splitext(os.path.basename(input_file))[0]  # Имя файла без расширения
            output_dir = os.path.join(input_dir, input_name)  # Папка для распаковки
        os.makedirs(output_dir, exist_ok=True)  # Создаём, если её нет
        config_file = os.path.join(output_dir, "config.json")
        unpack_image_file(input_file, output_dir, config_file)
    elif args.pack:
        assets=[]
        if os.path.isdir(args.assets[0]):
             input_dir=args.assets[0]
             config_file = os.path.join(input_dir, "config.json")
             config=load_json(config_file)
             for item in config:
                for filename in os.listdir(input_dir):
                     if filename.endswith('.bmp'):
                         if filename == item['name']+ '.bmp':
                             # сравним с оригиналом, надо чтобы битность и прочее соответствовало
                            data = bytes()
                            with open(os.path.join(input_dir, filename), "rb") as f:
                                data = f.read()
                            if is_bmp(data):
                                info=get_bmp_info(data)
                                del info['compression']
                                del info['file_size']
                                differences = {}
                                for key in info:
                                    if info[key] != item[key]:
                                        differences[key] = (info[key], item[key])
                                if differences:
                                    print("The " + filename + " does not match the specifications. The picture must be '16bits R5 G6 B5'.\n Fix the picture and try again.")
                                    sys.exit()
                                else:
                                    assets.append(os.path.join(input_dir, filename))
                            else:
                                print("The " + filename + " does not match the specifications. The picture must be BMP with '16bits R5 G6 B5'.\n Fix the picture and try again.")
                                sys.exit()
        pack_image_file(args.pack, assets, config)
    else:
        list_items(input_file)

if __name__ == "__main__":
    main()
