# Relatório de Teste de Penetração: VPS 

## Resumo
Este relatório mostra os resultados de um teste de penetração realizado na VPS do FuzzyLab com endereço IP 89.116.225.21. Foram utilizados vários scanners para identificar vulnerabilidades no servidor web. O teste focou na configuração do servidor web, em especial na falta de cabeçalhos de segurança críticos. Este relatório também fornece recomendações para mitigar as vulnerabilidades identificadas.

## Informações do Alvo
- ``IP: 89.116.225.21``
- ``Hostname: srv496937.hostgr.cloud``
- Serviços: HTTP (porta 80), HTTPS (porta 443), e outros serviços comuns.

### Metodologia
Os testes foram realizados seguindo a metodologia OSSTMM 3, abrangendo as seguintes áreas:

- Interações com superfícies de ataque (processos, portas e serviços).
- Inspeção de políticas e controles de segurança.
- Avaliação de vulnerabilidades.

## Ferramentas Utilizadas
- Nikto: Para escaneamento de vulnerabilidades web.
- Nmap: Para varredura de portas e identificação de serviços.
- WhatWeb: Para identificação de tecnologias web e informações do servidor.

## Descobertas e Vulnerabilidades

### 1. WhatWeb Scan

```
whatweb -v 89.116.225.21
```

Servidor HTTP: Caddy
Redirecionamento Permanente: https://89.116.225.21/

### 2. Nmap Scan

```
nmap -O 89.116.225.21
nmap --script ssl-enum-ciphers -p 443 89.116.225.21
```

#### Portas Abertas:
- 21/tcp (FTP)
- 22/tcp (SSH)
- 53/tcp (DNS)
- 80/tcp (HTTP)
- 111/tcp (RPCbind)
- 443/tcp (HTTPS)
- 8297/tcp (BLP3)

#### Ciphers TLSv1.3 Suportados:
- TLS_AES_128_GCM_SHA256
- TLS_AES_256_GCM_SHA384
- TLS_CHACHA20_POLY1305_SHA256


### 3. Nikto Scan

```
nikto -h 89.116.225.21
```

- ``X-Frame-Options``: Cabeçalho ausente. Pode permitir ataques de clickjacking.
- ``X-Content-Type-Options``: Cabeçalho ausente. Pode permitir ataques de MIME-sniffing.

Recomendação:
Adicionar os cabeçalhos de segurança ao servidor web Caddy.

Impacto:
A ausência desses cabeçalhos pode permitir ataques de clickjacking e MIME-sniffing, comprometendo a segurança dos usuários.


## Recomendações
Configuração de Cabeçalhos de Segurança no Caddy.

Para resolver as falhas identificadas, configure os cabeçalhos de segurança no Caddyfile.

#### Exemplo de Configuração:

```
example.com {
    header {
        X-Frame-Options "DENY"
        X-Content-Type-Options "nosniff"
    }
    # Outras configurações
}
```

## Verificação Pós-Configuração
Utilize o curl ou ferramentas online para verificar se os cabeçalhos foram aplicados corretamente

## Conclusão
A implementação dos cabeçalhos de segurança X-Frame-Options e X-Content-Type-Options no servidor Caddy é essencial para mitigar ataques de clickjacking e MIME-sniffing. A configuração correta e a verificação periódica das configurações aumentam a segurança do servidor web.

