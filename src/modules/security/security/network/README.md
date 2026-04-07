# Módulo de Segurança de Rede

## 1. Propósito

O módulo `network` lida com políticas de segurança em um nível mais baixo, relacionado à rede. Muitas dessas configurações são aplicadas na infraestrutura (Cloudflare, AWS WAF, etc.), mas são definidas e documentadas aqui para manter um registro centralizado e possibilitar a automação (Infrastructure as Code).

## 2. Estrutura

- **`dnsProtection.ts`**: Configurações relacionadas à segurança do DNS, como DNSSEC, para prevenir ataques de spoofing e envenenamento de cache DNS.
- **`firewallRules.ts`**: Define as regras do Web Application Firewall (WAF), como bloquear padrões de SQL Injection conhecidos.
- **`ipAllowlist.ts` / `ipBlocklist.ts`**: Mantém listas de IPs que devem ser sempre permitidos ou sempre bloqueados pelo firewall.
- **`networkPolicies.ts`**: Políticas de rede em um nível de orquestrador de contêineres (como Kubernetes), definindo quais serviços podem se comunicar entre si.
- **`portRestrictions.ts`**: Define quais portas de rede devem estar abertas ao público.
- **`trafficInspection.ts`**: Configurações para a inspeção de pacotes de rede (Deep Packet Inspection) em busca de atividades maliciosas.
- **`vpnEnforcement.ts`**: Políticas para exigir que o acesso a certos recursos seja feito através de uma VPN corporativa.