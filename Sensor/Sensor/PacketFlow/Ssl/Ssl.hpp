#ifndef SSL_PROXY_HPP
#define SSL_PROXY_HPP

#include "../../../util/util.hpp" // json, etc.

#define SSL_MIRROR_DUMMY_INTERFACE_NAME "SslMirrorDummy"

namespace NDR
{
    namespace Sensor
    {
        namespace SSL
        {
            namespace Cert
            {
                class CertCreator
                {
                public:
                    CertCreator(
                        std::string CertsDir = "Certs"
                    )
                    : CertsDir(CertsDir)
                    {}

                    bool Create_KeyCert(
                        std::string keyName = "default_sensor_private",

                        std::string certName = "default_sensor_cert",
                        std::string CountryCodeName = "KR",
                        std::string StateName = "Seoul",
                        std::string LogicallyName = "Seoul",
                        std::string OrganizationName = "SSLproxy",
                        std::string Organization_Unit = "MITM",
                        std::string CommonName = "SSLproxy Root CA",
                        
                        bool if_no_exists_create = true // 해당 개인키, 인증서가 없을 때만 생성하도록함 ( true )
                    )
                    {
                        return _make_all(
                            keyName,
                            certName,

                            CountryCodeName,
                            StateName,
                            LogicallyName,
                            OrganizationName,
                            Organization_Unit,
                            CommonName,
                            if_no_exists_create
                        );
                    }

                    std::string Get_KeyPath()
                    {
                        return PrivateKeyPath;
                    }
                    std::string Get_CrtPath()
                    {
                        return CertPath;
                    }

                    ~CertCreator() = default;

                private:
                    std::string CertsDir;
                    NDR::Util::File::FileHandler Filehandle;

                    std::string PrivateKeyPath;
                    std::string CertPath;

                    bool _make_all(
                        std::string keyName = "default_sensor_private",

                        std::string certName = "default_sensor_cert",
                        
                        std::string CountryCodeName = "KR",
                        std::string StateName = "Seoul",
                        std::string LogicallyName = "Seoul",
                        std::string OrganizationName = "SSLproxy",
                        std::string Organization_Unit = "MITM",
                        std::string CommonName = "SSLproxy Root CA",

                        bool if_no_exists_create = true
                    )
                    {
                        std::string KeyPath = CertsDir + "/" + keyName + ".key";
                        std::string CertSigningRequestPath = CertsDir + "/" + certName + ".csr";
                        std::string CrtPath = CertsDir + "/" + certName + ".crt";

                        // 파일 체크
                        if(if_no_exists_create)
                        {
                            if(_is_PrivateKey_and_Cert_exists(KeyPath, CrtPath))
                            {
                                PrivateKeyPath = KeyPath;
                                CertPath = CrtPath; 
                                return true; // 이미 파일이 있어서 성공
                            }
                                
                        }
                        


                        int ret = system(
                            std::string(
                                fmt::format(
                                    "openssl req -x509 -newkey rsa:2048 -keyout \"{}\" -out \"{}\" -sha256 -days 3650 -nodes -subj '/C={}/ST={}/L={}/O={}/OU={}/CN={}' -addext \"basicConstraints=critical,CA:TRUE,pathlen:0\" -addext \"keyUsage=critical,keyCertSign,cRLSign\" -addext \"subjectKeyIdentifier=hash\"",
                                    KeyPath,
                                    CrtPath,

                                    CountryCodeName,
                                    StateName,
                                    LogicallyName,
                                    OrganizationName,
                                    Organization_Unit,
                                    CommonName
                                )
                            ).c_str()
                        );
                        if(WEXITSTATUS(ret) == 0)
                        {
                            PrivateKeyPath = KeyPath;
                            CertPath = CrtPath;
                            return true;
                        }
                        else
                            return false;
                    }

                    bool _is_PrivateKey_and_Cert_exists(
                        std::string KeyPath,
                        std::string CrtPath
                    )
                    {
                        if( Filehandle.is_valid_file(KeyPath) && Filehandle.is_valid_file(CrtPath) )
                            return true;
                        else
                            return false;
                    }

                };
            }

            class SSLProxy_Manager
            {
                public:
                    SSLProxy_Manager(
                        std::string ServerIP = "0.0.0.0",
                        unsigned long ServerPORT = 8443
                    )
                    : ServerIP(ServerIP),
                    ServerPORT(ServerPORT)
                    {}
                    ~SSLProxy_Manager() = default;

                    bool Run(std::string KeyPath, std::string CertPath)
                    {
                        if(is_running)
                            return false;
                        
                        is_running = true;

                        pid_t pid = fork();
                        if(pid == 0) {
                            // 자식 프로세스
                            execlp("sslproxy", "sslproxy",
                                "-k", KeyPath.c_str(),
                                "-c", CertPath.c_str(),
                                "-P", "autossl",
                                ServerIP.c_str(),
                                std::to_string(ServerPORT).c_str(),
                                "-I", SSL_MIRROR_DUMMY_INTERFACE_NAME,
                                (char*)nullptr);

                            // execlp 실패 시
                            perror("execlp failed");
                            _exit(127);
                            is_running = false;
                            Proxy_ProcessId = 0;
                            return false;

                        } else if(pid > 0) {
                            // 부모 프로세스 → 바로 다음 코드 진행 (백그라운드처럼)
                            std::cout << "sslproxy PID: " << pid << std::endl;
                            Proxy_ProcessId = pid;
                        } else {
                            perror("fork failed");
                            is_running = false;
                            Proxy_ProcessId = 0;
                            return false;
                        }

                        return true;
                    }
                    
                    bool Stop()
                    {
                        if(!is_running || Proxy_ProcessId)
                            return false;
                        
                        // 종료 요청
                        if( kill(Proxy_ProcessId, SIGKILL) == 0 )
                        {
                            Proxy_ProcessId = 0;
                            return true;
                        }
                        else
                            return false;

                        
                    }

                private:
                    std::string ServerIP;
                    unsigned long ServerPORT;

                    bool is_running = false;
                    unsigned long long Proxy_ProcessId = 0;
            };
            
            class SSL_Manager
            {

                public:
                    SSL_Manager(
                        std::string CertsDir
                    )
                    : CertMaker(CertsDir)
                    {
                        if( !this->CertMaker.Create_KeyCert() )
                            throw std::runtime_error("CertMaker.Create_KeyCert() failed");

                        {
                            // SSLProxy -(Mirror)-> SSL_MIRROR_DUMMY_INTERFACE_NAME(dummy interface)
                            system(std::string(fmt::format("ip link add {} type dummy 2>/dev/null",SSL_MIRROR_DUMMY_INTERFACE_NAME )).c_str() );
                            system(std::string(fmt::format("ip link set {} up",SSL_MIRROR_DUMMY_INTERFACE_NAME )).c_str() );
                        }
                        
                    }

                    bool Run()
                    {
                        if(is_running)
                            return false;

                        // SSLProxy 실행 (백그라운드형)
                        is_running = SSL_Proxy.Run(
                            this->CertMaker.Get_KeyPath(),
                            this->CertMaker.Get_CrtPath()
                        );

                        return is_running;
                    }

                    bool Stop()
                    {
                        if(!is_running)
                            return false;

                        bool is_stop = SSL_Proxy.Stop();
                        if(!is_stop)
                            return false;

                        is_running = false;
                        return true;
                    }

                    ~SSL_Manager() = default;
                private:
                    bool is_running = false;
                    Cert::CertCreator CertMaker;
                    SSLProxy_Manager SSL_Proxy;

            };
        }
    }
}

#endif

/*

-> https://github.com/sonertari/SSLproxy/blob/master/LICENSE ( SSLProxy Open-Source )

BSD 2-Clause License

Copyright (c) 2017-2025, Soner Tari.
Copyright (c) 2009-2019, Daniel Roethlisberger and contributors.
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:
1. Redistributions of source code must retain the above copyright notice,
   this list of conditions and the following disclaimer.
2. Redistributions in binary form must reproduce the above copyright notice,
   this list of conditions and the following disclaimer in the documentation
   and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDER AND CONTRIBUTORS ``AS IS''
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
ARE DISCLAIMED.  IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
POSSIBILITY OF SUCH DAMAGE.
*/