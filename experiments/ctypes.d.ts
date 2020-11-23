// https://developer.mozilla.org/en-US/docs/Mozilla/js-ctypes
declare module ctypes {
    // https://developer.mozilla.org/en-US/docs/Mozilla/js-ctypes/js-ctypes_reference/CData
    interface CData<T extends CType> {
        readonly address: () => CDataPointerType<T>;
        readonly toSource: () => string;
        readonly toString: () => string;

        readonly constructor: T;
        value: any;
    }
    // https://developer.mozilla.org/en-US/docs/Mozilla/js-ctypes/js-ctypes_reference/CType
    interface CType<T extends string = "", U = CData<T>> {
        readonly array: (n?: number) => ArrayTypeI<CType<T, U>>;
        readonly toSource: () => string;
        readonly toString: () => string;

        readonly name: T;
        readonly ptr: PointerTypeI<CType<T, U>>;
        readonly size: number;

        readonly _underlyingType: U;
    }
    // https://developer.mozilla.org/en-US/docs/Mozilla/js-ctypes/js-ctypes_reference/Library
    interface Library {
        readonly close: () => void;
    }

    // https://developer.mozilla.org/en-US/docs/Mozilla/js-ctypes/js-ctypes_reference/PointerType
    interface PointerTypeI<T extends CType<any, any>> extends CType {
        (): CDataPointerType<T>;
        readonly ptr: PointerTypeI<PointerTypeI<T>>;

        readonly targetType: T;

        readonly _underlyingType: CDataPointerType<T>;
    }
    const PointerType: {
        new <T extends CType<any, any>>(type: T): PointerTypeI<T>;
        <T extends CType<any, any>>(type: T): PointerTypeI<T>;
    };
    interface CDataPointerType<T extends CType<any, any>> extends CData<PointerTypeI<T>> {
        readonly isNull: () => boolean;
        readonly increment: () => CDataPointerType<T>;
        readonly decrement: () => CDataPointerType<T>;
        contents: T["_underlyingType"];

        readonly readString: () => string;
    }

    // https://developer.mozilla.org/en-US/docs/Mozilla/js-ctypes/js-ctypes_reference/StructType
    interface StructTypeI extends CType<any, any> {
        (): CData<StructTypeI>;
        readonly ptr: PointerTypeI<StructTypeI>;
    }
    const StructType: {
        new(name: string, fields?): StructTypeI;
        (name: string, fields?): StructTypeI;
    };

    // https://developer.mozilla.org/en-US/docs/Mozilla/js-ctypes/js-ctypes_reference/ArrayType
    interface ArrayTypeI<T extends CType<any, any>> extends CType {
        (): CData<ArrayTypeI>;
        readonly ptr: PointerTypeI<ArrayTypeI<T>>;

        readonly _underlyingType: CDataArrayType<T>;
    }
    const ArrayType: {
        new <T extends CType<any, any>>(type: T, length?: number): ArrayTypeI<T>;
        <T extends CType<any, any>>(type: T, length?: number): ArrayTypeI<T>;
    }
    interface CDataArrayType<T extends CType<any, any>> extends CData<ArrayTypeI<T>> {
        [x: number]: T["_underlyingType"];
        readonly length: number;
    }

    // Predefined data types
    // https://developer.mozilla.org/en-US/docs/Mozilla/js-ctypes/js-ctypes_reference/ctypes#Predefined_data_types
    const int8_t: CType<"int8_t", number>;
    const uint8_t: CType<"uint8_t", number>;
    const int16_t: CType<"int16_t", number>;
    const uint16_t: CType<"uint16_t", number>;
    const int32_t: CType<"int32_t", number>;
    const uint32_t: CType<"uint32_t", number>;
    const int64_t: CType<"int64_t", number>;
    const uint64_t: CType<"uint64_t", number>;
    const float32_t: CType<"float32_t", number>;
    const float64_t: CType<"float64_t", number>;

    const bool: CType<"bool", boolean>;
    const short: CType<"short", number>;
    const unsigned_short: CType<"unsigned_short", number>;
    const int: CType<"int", number>;
    const unsigned_int: CType<"unsigned_int", number>;
    const long: CType<"long", number>;
    const unsigned_long: CType<"unsigned_long", number>;
    const long_long: CType<"long_long", number>;
    const unsigned_long_long: CType<"unsigned_long_long", number>;
    const float: CType<"float", number>;
    const double: CType<"double", number>;

    const char: CType<"char">;
    const signed_char: CType<"signed_char">;
    const unsigned_char: CType<"unsigned_char">;

    const size_t: CType<"size_t">;
    const ssize_t: CType<"ssize_t">;
    const intptr_t: CType<"intptr_t">;
    const uintptr_t: CType<"uintptr_t">;

    const jschar: CType<"jschar">;

    const void_t: CType<"void_t">;
    const voidptr_t: PointerTypeI<any>;

    const Int64: CType<"Int64">;
    const UInt64: CType<"UInt64">;

    // Methods
    // https://developer.mozilla.org/en-US/docs/Mozilla/js-ctypes/js-ctypes_reference/ctypes#Methods
    const cast: <T extends CType<any, any> | CDataPointerType<any>>(data: CData<any>, type: T) => T["_underlyingType"];
    const libraryName: (name: string) => string;
    const open: (libSpec: string) => Library;

    // https://developer.mozilla.org/en-US/docs/Mozilla/js-ctypes/js-ctypes_reference/Library
    interface Library {
        readonly close: () => void;
        readonly declare: <RT extends CType<any, any> | CDataPointerType<any>>(
            name: string,
            abi?: ABI,
            returnType?: RT,
            ...argType1: CType<any, any>[]
        ) => () => RT["_underlyingType"];
    }

    // https://developer.mozilla.org/en-US/docs/Mozilla/js-ctypes/js-ctypes_reference/ABI
    interface ABI { ABI: never };

    // Properties
    // https://developer.mozilla.org/en-US/docs/Mozilla/js-ctypes/js-ctypes_reference/ctypes#Properties
    const errno: number;
    const winLastError: number | undefined;

    // Constants
    // https://developer.mozilla.org/en-US/docs/Mozilla/js-ctypes/js-ctypes_reference/ctypes#Constants
    const default_abi: ABI;
    const stdcall_abi: ABI;
    const winapi_abi: ABI;
}
