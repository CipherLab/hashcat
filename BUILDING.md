# Building Hashcat

## Prerequisites

- GNU make
- GCC or Clang compiler
- OpenCL headers and runtime
- CUDA toolkit (optional, for NVIDIA GPU support)

## Basic Build

1. Clone the repository:
```bash
git clone https://github.com/hashcat/hashcat.git
cd hashcat
```

2. Build hashcat:
```bash
make
```

3. Install (optional):
```bash
sudo make install
```

## Building with Brain Support

Hashcat Brain is included in the main hashcat build by default. No additional steps are required to enable it.

## Common Issues

### Missing OpenCL

If you get OpenCL-related errors, install the required packages:

For Ubuntu/Debian:
```bash
sudo apt-get install ocl-icd-opencl-dev
```

For CentOS/RHEL:
```bash
sudo yum install opencl-headers ocl-icd-devel
```

### Missing CUDA

For NVIDIA GPU support, install the CUDA toolkit from NVIDIA's website or package manager:

For Ubuntu/Debian:
```bash
sudo apt-get install nvidia-cuda-toolkit
```

### Build Options

- `make ENABLE_BRAIN=0` - Build without Brain support
- `make OPENCL=0` - Build without OpenCL support
- `make CUDA=0` - Build without CUDA support

## Testing the Build

After building, you can test the installation:

```bash
./hashcat --version
```

This should display the hashcat version information if the build was successful.
