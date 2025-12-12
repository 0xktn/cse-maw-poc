import ctypes
import base64

# Load the NSM library
# libnsm.so is copied to /usr/lib64/libnsm.so in the Dockerfile
try:
    libnsm = ctypes.CDLL("libnsm.so")
except OSError:
    # Fallback paths or error handling if running locally/testing
    try:
        libnsm = ctypes.CDLL("/usr/lib64/libnsm.so")
    except OSError:
        libnsm = None

# Define Structs
class NsmAttestationDocRequest(ctypes.Structure):
    _fields_ = [
        ("public_key", ctypes.POINTER(ctypes.c_ubyte)),
        ("public_key_len", ctypes.c_uint32),
        ("nonce", ctypes.POINTER(ctypes.c_ubyte)),
        ("nonce_len", ctypes.c_uint32),
        ("user_data", ctypes.POINTER(ctypes.c_ubyte)),
        ("user_data_len", ctypes.c_uint32),
    ]

# Define Function Prototypes
if libnsm:
    # int nsm_lib_init(void);
    libnsm.nsm_lib_init.restype = ctypes.c_int
    libnsm.nsm_lib_init.argtypes = []

    # int nsm_lib_exit(void);
    libnsm.nsm_lib_exit.restype = ctypes.c_int
    libnsm.nsm_lib_exit.argtypes = []

    # int nsm_fd_open(void);
    libnsm.nsm_fd_open.restype = ctypes.c_int
    libnsm.nsm_fd_open.argtypes = []

    # void nsm_fd_close(int fd);
    libnsm.nsm_fd_close.restype = None
    libnsm.nsm_fd_close.argtypes = [ctypes.c_int]

    # int nsm_get_attestation_doc(int fd,
    #                             const struct nsm_attestation_doc_request *request,
    #                             uint32_t request_len,
    #                             uint8_t *attestation_doc,
    #                             uint32_t *attestation_doc_len);
    libnsm.nsm_get_attestation_doc.restype = ctypes.c_int
    libnsm.nsm_get_attestation_doc.argtypes = [
        ctypes.c_int,
        ctypes.POINTER(NsmAttestationDocRequest),
        ctypes.c_uint32,
        ctypes.POINTER(ctypes.c_ubyte),
        ctypes.POINTER(ctypes.c_uint32)
    ]

def get_attestation_doc_b64():
    """
    Get the attestation document from the NSM and return it as a base64 string.
    Returns: (base64_string, error_message)
    """
    if not libnsm:
        return None, "libnsm not loaded"

    # Initialize library
    if libnsm.nsm_lib_init() != 0:
        return None, "Failed to initialize NSM library"

    fd = libnsm.nsm_fd_open()
    if fd < 0:
        libnsm.nsm_lib_exit()
        return None, "Failed to open NSM device"

    try:
        # Prepare empty request (no nonce/user_data/public_key needed for basic attestation)
        req = NsmAttestationDocRequest()
        req.public_key = None
        req.public_key_len = 0
        req.nonce = None
        req.nonce_len = 0
        req.user_data = None
        req.user_data_len = 0
        
        # Buffer for output (16KB is generous max for attestation doc)
        buf_len = 16 * 1024
        buf = (ctypes.c_ubyte * buf_len)()
        out_len = ctypes.c_uint32(buf_len)
        
        res = libnsm.nsm_get_attestation_doc(
            fd, 
            ctypes.byref(req), 
            ctypes.sizeof(req), 
            buf, 
            ctypes.byref(out_len)
        )
        
        if res != 0:
             return None, f"nsm_get_attestation_doc failed with code {res}"
            
        # Extract data
        doc_bytes = bytes(buf[:out_len.value])
        return base64.b64encode(doc_bytes).decode('utf-8'), None

    except Exception as e:
        # Return error message for debugging
        return None, str(e)
    finally:
        libnsm.nsm_fd_close(fd)
        libnsm.nsm_lib_exit()
