# [VateX – eXtend the Edge](https://github.com/lastime1650/VateX)

<div align="center">
  <img
    src="https://github.com/lastime1650/VateX/blob/main/images/VATEX.png"
    alt="VATEX LOGO"
    width="500"
  />
</div>

---

# VateX Series - VateX EVIDENTIA NDR

<div align="center">
  <img
    src="https://github.com/lastime1650/VateX/blob/mainv2/images/VATEX_NDR_RENDERED.png"
    alt="VATEX NDR"
    width="400"
  />
</div>

---

**NOTITIA** means *knowledge* or *information* in Latin.  
VateX NOTITIA extends your threat detection across network traffic, delivering intelligent analysis and early warning of hidden or lateral attacks, ensuring your network remains transparent and secure. 🔍📡

---

## Key Components

1. **eBPF Tc filter based packet receive Sensor** `(C/C++)`
2. **C++ based NDR Server** `(C/C++)`

> [!Note]
> ⚠️ Events collected by the Agent are sent to a `Kafka` server, so please ensure the Kafka platform is installed and running beforehand.
> **Data Flow:** Sensor(Packet Agent) → Kafka → NDR

---

## Core Analysis Techniques

1. **Flow based Packet Analysis**
   The sensor collects packet flow sessions, which are analyzed

---

## Supported Platforms

1. [**Linux**](https://github.com/lastime1650/VATEX_EVIDENTIA_EDR/tree/Linux) `[eBPF-based, Kernel 6.10 or newer]`

---

## Future Plans & Improvements

We continuously strive to enhance detection capabilities and are performing extensive testing to make the solution more robust.

