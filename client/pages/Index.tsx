import { useState, useEffect, useRef } from "react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Textarea } from "@/components/ui/textarea";
import { Badge } from "@/components/ui/badge";
import { Separator } from "@/components/ui/separator";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Checkbox } from "@/components/ui/checkbox";
import {
  Copy,
  Download,
  Router,
  Network,
  Settings,
  Info,
  Play,
  CheckCircle,
  HelpCircle,
  Shield,
  Globe,
  Code,
  Terminal,
  Eye,
  EyeOff,
  Plus,
  X,
} from "lucide-react";
import { useToast } from "@/hooks/use-toast";

interface NetworkConfig {
  providerName: string;
  ispGateway: string;
  inPort: string;
  outPort: string;
  networkBase: string;
  dhcpStart: string;
  dhcpEnd: string;
}

interface FirewallRule {
  id: string;
  name: string;
  description: string;
  enabled: boolean;
  category: string;
}

interface ContentBlocking {
  blockAllSites: boolean;
  allowOnlySpecific: boolean;
  allowedSites: string[];
  blockCategories: {
    social: boolean;
    gambling: boolean;
    adult: boolean;
    gaming: boolean;
    streaming: boolean;
    shopping: boolean;
    news: boolean;
    entertainment: boolean;
  };
}

interface ExternalAccess {
  enabled: boolean;
  publicIP: string;
  applicationPort: string;
  enablePortForwarding: boolean;
  firewallOpen: boolean;
}

export default function Index() {
  const [activeTab, setActiveTab] = useState("rede");
  const [showTerminal, setShowTerminal] = useState(false);
  const [terminalOutput, setTerminalOutput] = useState("");
  const [isGenerating, setIsGenerating] = useState(false);
  const [newAllowedSite, setNewAllowedSite] = useState("");
  const [showManualCopy, setShowManualCopy] = useState(false);
  const terminalRef = useRef<HTMLDivElement>(null);

  const [networkConfig, setNetworkConfig] = useState<NetworkConfig>({
    providerName: "Provedor Local",
    ispGateway: "192.168.18.1",
    inPort: "1",
    outPort: "5",
    networkBase: "10.0.0",
    dhcpStart: "10.0.0.10",
    dhcpEnd: "10.0.0.100",
  });

  const [firewallRules, setFirewallRules] = useState<FirewallRule[]>([
    {
      id: "block_winbox",
      name: "Bloquear WinBox Externo",
      description: "Impede acesso ao WinBox de fora da rede",
      enabled: true,
      category: "security",
    },
    {
      id: "block_ssh",
      name: "Bloquear SSH Externo",
      description: "Impede acesso SSH de fora da rede",
      enabled: true,
      category: "security",
    },
    {
      id: "block_telnet",
      name: "Bloquear Telnet",
      description: "Desabilita acesso via Telnet",
      enabled: true,
      category: "security",
    },
    {
      id: "block_p2p",
      name: "Bloquear P2P/Torrent",
      description: "Bloqueia tráfego de BitTorrent e P2P",
      enabled: false,
      category: "traffic",
    },
    {
      id: "limit_bandwidth",
      name: "Limitar Largura de Banda",
      description: "Aplica limite de velocidade por usuário",
      enabled: false,
      category: "traffic",
    },
    {
      id: "dos_protection",
      name: "Proteção DDoS",
      description: "Protege contra ataques de negação de serviço",
      enabled: true,
      category: "security",
    },
    {
      id: "port_scan_detect",
      name: "Detectar Port Scan",
      description: "Detecta e bloqueia tentativas de port scan",
      enabled: true,
      category: "security",
    },
  ]);

  const [contentBlocking, setContentBlocking] = useState<ContentBlocking>({
    blockAllSites: false,
    allowOnlySpecific: false,
    allowedSites: [],
    blockCategories: {
      social: false,
      gambling: false,
      adult: false,
      gaming: false,
      streaming: false,
      shopping: false,
      news: false,
      entertainment: false,
    },
  });

  const [externalAccess, setExternalAccess] = useState<ExternalAccess>({
    enabled: false,
    publicIP: "",
    applicationPort: "80",
    enablePortForwarding: true,
    firewallOpen: true,
  });

  const [generatedScript, setGeneratedScript] = useState("");
  const { toast } = useToast();

  const toggleFirewallRule = (ruleId: string) => {
    setFirewallRules((prev) =>
      prev.map((rule) =>
        rule.id === ruleId ? { ...rule, enabled: !rule.enabled } : rule,
      ),
    );
  };

  const toggleBlockCategory = (
    category: keyof ContentBlocking["blockCategories"],
  ) => {
    setContentBlocking((prev) => ({
      ...prev,
      blockCategories: {
        ...prev.blockCategories,
        [category]: !prev.blockCategories[category],
      },
    }));
  };

  const addAllowedSite = () => {
    if (newAllowedSite.trim()) {
      setContentBlocking((prev) => ({
        ...prev,
        allowedSites: [...prev.allowedSites, newAllowedSite.trim()],
      }));
      setNewAllowedSite("");
    }
  };

  const removeAllowedSite = (index: number) => {
    setContentBlocking((prev) => ({
      ...prev,
      allowedSites: prev.allowedSites.filter((_, i) => i !== index),
    }));
  };

  const generateContentBlockingRules = () => {
    let rules = "";

    // Bloquear todos os sites
    if (contentBlocking.blockAllSites) {
      rules += `/ip firewall filter
add action=accept chain=forward connection-state=established,related
add action=drop chain=forward dst-port=80,443,8080 protocol=tcp
add action=drop chain=forward dst-port=53 protocol=udp
`;
      return rules;
    }

    // Permitir apenas sites específicos
    if (
      contentBlocking.allowOnlySpecific &&
      contentBlocking.allowedSites.length > 0
    ) {
      // Criar address-list com sites permitidos
      contentBlocking.allowedSites.forEach((site) => {
        rules += `/ip firewall address-list
add address=${site} list=sites-permitidos
`;
      });

      rules += `/ip firewall filter
add action=accept chain=forward connection-state=established,related
add action=accept chain=forward dst-address-list=sites-permitidos dst-port=80,443 protocol=tcp
add action=drop chain=forward dst-port=80,443,8080 protocol=tcp
add action=drop chain=forward dst-port=53 protocol=udp
`;
      return rules;
    }

    // Bloqueios por categoria
    if (contentBlocking.blockCategories.social) {
      rules += `/ip firewall layer7-protocol
add name=redes-sociais regexp="(facebook|instagram|twitter|tiktok|snapchat|linkedin|pinterest|reddit|discord|telegram|whatsapp)"
/ip firewall filter
add action=drop chain=forward layer7-protocol=redes-sociais
`;
    }

    if (contentBlocking.blockCategories.gambling) {
      rules += `/ip firewall layer7-protocol
add name=jogos-aposta regexp="(bet365|betfair|pokerstars|888poker|bwin|unibet|ladbrokes|williamhill|betway|casino|poker|bingo|slot)"
/ip firewall filter
add action=drop chain=forward layer7-protocol=jogos-aposta
`;
    }

    if (contentBlocking.blockCategories.adult) {
      rules += `/ip firewall layer7-protocol
add name=conteudo-adulto regexp="(porn|xxx|sex|adult|erotic|nude|nsfw|xvideos|pornhub|redtube|xhamster|youporn)"
/ip firewall filter
add action=drop chain=forward layer7-protocol=conteudo-adulto
`;
    }

    if (contentBlocking.blockCategories.gaming) {
      rules += `/ip firewall layer7-protocol
add name=jogos-online regexp="(steam|epicgames|origin|uplay|battle\\.net|riotgames|minecraft|fortnite|pubg|valorant|csgo|dota)"
/ip firewall filter
add action=drop chain=forward layer7-protocol=jogos-online
`;
    }

    if (contentBlocking.blockCategories.streaming) {
      rules += `/ip firewall layer7-protocol
add name=streaming regexp="(netflix|youtube|spotify|twitch|amazon.*video|hulu|disney|globoplay|paramount|hbo)"
/ip firewall filter
add action=drop chain=forward layer7-protocol=streaming
`;
    }

    if (contentBlocking.blockCategories.shopping) {
      rules += `/ip firewall layer7-protocol
add name=compras regexp="(amazon|mercadolivre|americanas|magazine|submarino|casasbahia|extra|shoptime|aliexpress|ebay)"
/ip firewall filter
add action=drop chain=forward layer7-protocol=compras
`;
    }

    if (contentBlocking.blockCategories.news) {
      rules += `/ip firewall layer7-protocol
add name=noticias regexp="(globo|uol|folha|estadao|g1|r7|band|sbt|record|cnn|bbc)"
/ip firewall filter
add action=drop chain=forward layer7-protocol=noticias
`;
    }

    if (contentBlocking.blockCategories.entertainment) {
      rules += `/ip firewall layer7-protocol
add name=entretenimento regexp="(buzzfeed|9gag|imgur|memes|humor|diversao|entretenimento|cinema|tv|series)"
/ip firewall filter
add action=drop chain=forward layer7-protocol=entretenimento
`;
    }

    return rules;
  };

  const generateCompleteScript = () => {
    const script =
      `# Configuração Completa MikroTik - Gerado automaticamente
# Data: ${new Date().toLocaleString("pt-BR")}
# Provedor: ${networkConfig.providerName} (${networkConfig.ispGateway})

# === CONFIGURAÇÃO BÁSICA DE REDE ===
# Provedor: ${networkConfig.providerName}
# Gateway: ${networkConfig.ispGateway}

# Criar bridge para rede local
/interface bridge
add name=bridge-local

# Adicionar apenas as portas LAN à bridge (não incluir a WAN)
/interface bridge port

# Configurar endereços IP
/ip address
add address=${networkConfig.networkBase}.1/24 interface=bridge-local network=${networkConfig.networkBase}.0

# Configurar cliente DHCP na interface WAN
/ip dhcp-client
add interface=ether${networkConfig.inPort} disabled=no

# Configurar pool DHCP para rede local
/ip pool
add name=dhcp-pool-local ranges=${networkConfig.dhcpStart}-${networkConfig.dhcpEnd}

# Configurar servidor DHCP
/ip dhcp-server
add address-pool=dhcp-pool-local interface=bridge-local name=dhcp-server-local

# Configurar rede DHCP
/ip dhcp-server network
add address=${networkConfig.networkBase}.0/24 gateway=${networkConfig.networkBase}.1 dns-server=8.8.8.8,8.8.4.4

# Configurar DNS
/ip dns
set allow-remote-requests=yes servers=8.8.8.8,1.1.1.1

# Configurar NAT para acesso à internet
/ip firewall nat
add action=masquerade chain=srcnat out-interface=ether${networkConfig.inPort}

# Configurar rota padrão
/ip route
add distance=1 gateway=${networkConfig.ispGateway}

` +
      // Firewall Rules
      `# === REGRAS DE FIREWALL E SEGURANÇA ===
` +
      (firewallRules.find((r) => r.id === "block_winbox")?.enabled
        ? `/ip firewall filter
add action=drop chain=input dst-port=8291 in-interface=ether${networkConfig.inPort} protocol=tcp
`
        : "") +
      (firewallRules.find((r) => r.id === "block_ssh")?.enabled
        ? `/ip firewall filter
add action=drop chain=input dst-port=22 in-interface=ether${networkConfig.inPort} protocol=tcp
`
        : "") +
      (firewallRules.find((r) => r.id === "block_telnet")?.enabled
        ? `/ip firewall filter
add action=drop chain=input dst-port=23 protocol=tcp
`
        : "") +
      (firewallRules.find((r) => r.id === "dos_protection")?.enabled
        ? `/ip firewall filter
add action=drop chain=input connection-limit=10,32 protocol=tcp
add action=drop chain=input connection-state=new limit=50,5:packet protocol=tcp tcp-flags=syn
`
        : "") +
      (firewallRules.find((r) => r.id === "port_scan_detect")?.enabled
        ? `/ip firewall filter
add action=add-src-to-address-list address-list=port-scanners address-list-timeout=1w chain=input protocol=tcp psd=21,3s,3,1
add action=drop chain=input src-address-list=port-scanners
`
        : "") +
      (firewallRules.find((r) => r.id === "block_p2p")?.enabled
        ? `/ip firewall filter
add action=drop chain=forward p2p=all-p2p
`
        : "") +
      (firewallRules.find((r) => r.id === "limit_bandwidth")?.enabled
        ? `/queue simple
add name=limite-geral target=${networkConfig.networkBase}.0/24 max-limit=50M/50M
`
        : "") +
      // Content Blocking Rules
      `
# === BLOQUEIO DE CONTEÚDO ===
` +
      generateContentBlockingRules() +
      // External Access
      (externalAccess.enabled &&
      externalAccess.enablePortForwarding &&
      externalAccess.applicationPort
        ? `
# === ACESSO EXTERNO ===
# IP Público: ${externalAccess.publicIP || "Configurar no provedor"}
/ip firewall nat
add action=dst-nat chain=dstnat dst-port=${externalAccess.applicationPort} in-interface=ether${networkConfig.inPort} protocol=tcp to-addresses=${networkConfig.networkBase}.10 to-ports=${externalAccess.applicationPort}
` +
          (externalAccess.firewallOpen
            ? `/ip firewall filter
add action=accept chain=input dst-port=${externalAccess.applicationPort} in-interface=ether${networkConfig.inPort} protocol=tcp
`
            : "")
        : "") +
      `
# === CONFIGURA��ÃO FINALIZADA ===
# Provedor: ${networkConfig.providerName}
# Configuração aplicada com sucesso!
`;

    return script;
  };

  // Função para remover comentários do script
  const removeCommentsFromScript = (script: string) => {
    return script
      .split("\n")
      .filter((line) => !line.trim().startsWith("#"))
      .filter((line) => line.trim() !== "")
      .join("\n");
  };

  const scrollToBottom = () => {
    if (terminalRef.current) {
      terminalRef.current.scrollTop = terminalRef.current.scrollHeight;
    }
  };

  const typewriterEffect = async (text: string) => {
    setTerminalOutput("");
    setIsGenerating(true);

    const lines = text.split("\n");
    let currentOutput = "";

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];

      if (line.startsWith("#")) {
        // Comentários aparecem mais rápido
        currentOutput += line + "\n";
        setTerminalOutput(currentOutput);
        scrollToBottom();
        await new Promise((resolve) => setTimeout(resolve, 100));
      } else if (line.trim() === "") {
        // Linhas vazias aparecem instantaneamente
        currentOutput += line + "\n";
        setTerminalOutput(currentOutput);
        scrollToBottom();
      } else {
        // Comandos aparecem letra por letra
        for (let j = 0; j <= line.length; j++) {
          const currentLine = currentOutput + line.substring(0, j);
          setTerminalOutput(currentLine + (j < line.length ? "█" : "\n"));
          scrollToBottom();
          await new Promise((resolve) => setTimeout(resolve, 20));
        }
        currentOutput += line + "\n";
      }
    }

    setIsGenerating(false);
  };

  const generateCompleteScriptWithAnimation = async () => {
    const script = generateCompleteScript();
    setGeneratedScript(script);
    setShowTerminal(true);
    await typewriterEffect(script);

    toast({
      title: "🎉 Configuração Completa Gerada!",
      description: `Script para ${networkConfig.providerName} pronto!`,
    });
  };

    const copyToClipboard = async () => {
    const scriptWithoutComments = removeCommentsFromScript(generatedScript);
    try {
      // Tentar usar a API moderna do clipboard
      if (navigator.clipboard && window.isSecureContext) {
        await navigator.clipboard.writeText(scriptWithoutComments);
        toast({
          title: "📋 Script copiado!",
          description:
            "Script sem comentários copiado. Cole no terminal do MikroTik.",
        });
        return;
      } else {
        // Fallback para navegadores antigos ou contextos não seguros
        const textArea = document.createElement("textarea");
        textArea.value = scriptWithoutComments;
        textArea.style.position = "fixed";
        textArea.style.left = "-999999px";
        textArea.style.top = "-999999px";
        textArea.style.opacity = "0";
        document.body.appendChild(textArea);
        textArea.focus();
        textArea.select();
        textArea.setSelectionRange(0, 99999);

        const successful = document.execCommand("copy");
        document.body.removeChild(textArea);

        if (successful) {
          toast({
            title: "📋 Script copiado!",
            description:
              "Script sem comentários copiado. Cole no terminal do MikroTik.",
          });
          return;
        }
      }
    } catch (err) {
      console.error("Erro ao copiar:", err);
    }

    // Se chegou aqui, mostrar opção manual
    setShowManualCopy(true);
    toast({
      title: "🔄 Cópia Manual Ativada",
      description: "Use a área de texto abaixo para copiar o script manualmente.",
    });
  };

  const downloadScript = () => {
    const scriptWithoutComments = removeCommentsFromScript(generatedScript);
    const blob = new Blob([scriptWithoutComments], { type: "text/plain" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `configuracao-${networkConfig.providerName.toLowerCase().replace(/\s+/g, "-")}-mikrotik.rsc`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
    toast({
      title: "💾 Arquivo baixado!",
      description: `Script sem comentários salvo como: configuracao-${networkConfig.providerName.toLowerCase().replace(/\s+/g, "-")}-mikrotik.rsc`,
    });
  };

  const getRulesByCategory = (category: string) => {
    return firewallRules.filter((rule) => rule.category === category);
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-blue-50 via-white to-green-50">
      <div className="container mx-auto px-4 py-8">
        {/* Header */}
        <div className="text-center mb-8">
          <div className="flex items-center justify-center gap-3 mb-4">
            <Router className="h-10 w-10 text-mikrotik" />
            <h1 className="text-4xl font-bold text-gray-900">
              Centro Administrativo MikroTik
            </h1>
          </div>
          <p className="text-lg text-gray-600 max-w-3xl mx-auto mb-4">
            Configure sua rede completa:{" "}
            <strong>
              Rede básica + Firewall + Controle de conteúdo + Acesso externo
            </strong>
            <br />
            <em>Para qualquer provedor de internet!</em>
          </p>
          <div className="flex items-center justify-center gap-4">
            <Badge
              variant="outline"
              className="flex items-center gap-1 text-mikrotik border-mikrotik"
            >
              <Network className="h-3 w-3" />
              Configuração Completa
            </Badge>
            <Badge
              variant="outline"
              className="flex items-center gap-1 text-network border-network"
            >
              <Shield className="h-3 w-3" />
              Firewall Avançado
            </Badge>
            <Badge
              variant="outline"
              className="flex items-center gap-1 text-purple-600 border-purple-600"
            >
              <Globe className="h-3 w-3" />
              Controle de Conteúdo
            </Badge>
          </div>
        </div>

        {/* Tabs System */}
        <Card className="max-w-7xl mx-auto shadow-xl">
          <CardHeader className="bg-gradient-to-r from-mikrotik/10 via-network/10 to-purple-100">
            <CardTitle className="text-2xl text-center">
              🔧 Configurador MikroTik
            </CardTitle>
            <CardDescription className="text-center text-lg">
              Configure passo a passo sua rede completa
            </CardDescription>
          </CardHeader>
          <CardContent className="p-0">
            <Tabs
              value={activeTab}
              onValueChange={setActiveTab}
              className="w-full"
            >
              <TabsList className="grid w-full grid-cols-4 bg-gray-50">
                <TabsTrigger
                  value="rede"
                  className="flex items-center gap-2 text-base py-3"
                >
                  <Network className="h-4 w-4" />
                  🌐 REDE
                </TabsTrigger>
                <TabsTrigger
                  value="firewall"
                  className="flex items-center gap-2 text-base py-3"
                >
                  <Shield className="h-4 w-4" />
                  🛡️ FIREWALL
                </TabsTrigger>
                <TabsTrigger
                  value="externo"
                  className="flex items-center gap-2 text-base py-3"
                >
                  <Globe className="h-4 w-4" />
                  🌍 ACESSO EXTERNO
                </TabsTrigger>
                <TabsTrigger
                  value="script"
                  className="flex items-center gap-2 text-base py-3"
                >
                  <Code className="h-4 w-4" />
                  📜 GERAR SCRIPT
                </TabsTrigger>
              </TabsList>

              {/* ABA REDE */}
              <TabsContent value="rede" className="p-6 space-y-6">
                <div className="text-center mb-6">
                  <h2 className="text-2xl font-bold text-mikrotik mb-2">
                    🌐 Configuração de Rede
                  </h2>
                  <p className="text-gray-600">
                    Configure as informações básicas da sua rede
                  </p>
                </div>

                <div className="grid md:grid-cols-2 gap-6">
                  <div className="space-y-4">
                    <div className="space-y-2">
                      <Label
                        htmlFor="providerName"
                        className="text-base font-medium flex items-center gap-2"
                      >
                        🏢 Nome do Provedor de Internet
                      </Label>
                      <Input
                        id="providerName"
                        value={networkConfig.providerName}
                        onChange={(e) =>
                          setNetworkConfig({
                            ...networkConfig,
                            providerName: e.target.value,
                          })
                        }
                        placeholder="Ex: GIGA+, NET, Vivo, TIM..."
                        className="text-base"
                      />
                      <p className="text-sm text-gray-600">
                        Nome da sua operadora (aparecerá nos comentários do
                        script)
                      </p>
                    </div>

                    <div className="space-y-2">
                      <Label
                        htmlFor="ispGateway"
                        className="text-base font-medium flex items-center gap-2"
                      >
                        🌐 IP Gateway do Provedor
                      </Label>
                      <Input
                        id="ispGateway"
                        value={networkConfig.ispGateway}
                        onChange={(e) =>
                          setNetworkConfig({
                            ...networkConfig,
                            ispGateway: e.target.value,
                          })
                        }
                        className="text-base"
                      />
                      <p className="text-sm text-gray-600">
                        IP do gateway fornecido pelo{" "}
                        {networkConfig.providerName}
                      </p>
                    </div>

                    <div className="grid grid-cols-2 gap-4">
                      <div className="space-y-2">
                        <Label className="text-base font-medium">
                          📥 Porta Entrada
                        </Label>
                        <Input
                          value={networkConfig.inPort}
                          onChange={(e) =>
                            setNetworkConfig({
                              ...networkConfig,
                              inPort: e.target.value,
                            })
                          }
                          className="text-base"
                        />
                        <p className="text-sm text-gray-600">
                          Cabo do provedor
                        </p>
                      </div>
                      <div className="space-y-2">
                        <Label className="text-base font-medium">
                          📤 Porta Saída
                        </Label>
                        <Input
                          value={networkConfig.outPort}
                          onChange={(e) =>
                            setNetworkConfig({
                              ...networkConfig,
                              outPort: e.target.value,
                            })
                          }
                          className="text-base"
                        />
                        <p className="text-sm text-gray-600">
                          Seus dispositivos
                        </p>
                      </div>
                    </div>
                  </div>

                  <div className="space-y-4">
                    <div className="space-y-2">
                      <Label className="text-base font-medium">
                        🏠 Rede Local (Base)
                      </Label>
                      <Input
                        value={networkConfig.networkBase}
                        onChange={(e) =>
                          setNetworkConfig({
                            ...networkConfig,
                            networkBase: e.target.value,
                          })
                        }
                        className="text-base"
                      />
                      <p className="text-sm text-gray-600">
                        IPs serão: {networkConfig.networkBase}.10,{" "}
                        {networkConfig.networkBase}.11...
                      </p>
                    </div>

                    <div className="grid grid-cols-2 gap-4">
                      <div className="space-y-2">
                        <Label className="text-base font-medium">
                          🔢 DHCP Início
                        </Label>
                        <Input
                          value={networkConfig.dhcpStart}
                          onChange={(e) =>
                            setNetworkConfig({
                              ...networkConfig,
                              dhcpStart: e.target.value,
                            })
                          }
                          className="text-base"
                        />
                      </div>
                      <div className="space-y-2">
                        <Label className="text-base font-medium">
                          🔢 DHCP Fim
                        </Label>
                        <Input
                          value={networkConfig.dhcpEnd}
                          onChange={(e) =>
                            setNetworkConfig({
                              ...networkConfig,
                              dhcpEnd: e.target.value,
                            })
                          }
                          className="text-base"
                        />
                      </div>
                    </div>
                  </div>
                </div>

                <div className="text-center pt-4">
                  <Button
                    onClick={() => setActiveTab("firewall")}
                    className="bg-mikrotik hover:bg-mikrotik/90 text-lg px-8 py-3"
                  >
                    Próximo: Configurar Firewall 🛡️
                  </Button>
                </div>
              </TabsContent>

              {/* ABA FIREWALL */}
              <TabsContent value="firewall" className="p-6 space-y-6">
                <div className="text-center mb-6">
                  <h2 className="text-2xl font-bold text-network mb-2">
                    🛡️ Firewall e Controle de Conteúdo
                  </h2>
                  <p className="text-gray-600">
                    Configure segurança e bloqueios de conteúdo
                  </p>
                </div>

                {/* Controles Extremos */}
                <Card className="border-2 border-red-200 bg-red-50">
                  <CardHeader>
                    <CardTitle className="flex items-center gap-2 text-lg text-red-700">
                      <Shield className="h-5 w-5" />
                      🚫 Controles Extremos
                    </CardTitle>
                  </CardHeader>
                  <CardContent className="space-y-4">
                    <div className="flex items-center space-x-3">
                      <Checkbox
                        id="blockAllSites"
                        checked={contentBlocking.blockAllSites}
                        onCheckedChange={(checked) =>
                          setContentBlocking({
                            ...contentBlocking,
                            blockAllSites: !!checked,
                            allowOnlySpecific: false,
                          })
                        }
                        className="w-5 h-5"
                      />
                      <div className="grid gap-1.5 leading-none">
                        <label
                          htmlFor="blockAllSites"
                          className="text-base font-semibold cursor-pointer text-red-700"
                        >
                          🔒 Bloquear TODOS OS SITES
                        </label>
                        <p className="text-sm text-red-600">
                          ATENÇÃO: Bloqueia completamente o acesso à internet
                        </p>
                      </div>
                    </div>

                    <Separator />

                    <div className="space-y-4">
                      <div className="flex items-center space-x-3">
                        <Checkbox
                          id="allowOnlySpecific"
                          checked={contentBlocking.allowOnlySpecific}
                          onCheckedChange={(checked) =>
                            setContentBlocking({
                              ...contentBlocking,
                              allowOnlySpecific: !!checked,
                              blockAllSites: false,
                            })
                          }
                          className="w-5 h-5"
                        />
                        <div className="grid gap-1.5 leading-none">
                          <label
                            htmlFor="allowOnlySpecific"
                            className="text-base font-semibold cursor-pointer text-orange-700"
                          >
                            ✅ Permitir APENAS sites específicos
                          </label>
                          <p className="text-sm text-orange-600">
                            Bloqueia tudo, exceto os sites que você adicionar
                            abaixo
                          </p>
                        </div>
                      </div>

                      {contentBlocking.allowOnlySpecific && (
                        <div className="space-y-3 ml-8">
                          <div className="flex gap-2">
                            <Input
                              placeholder="Ex: google.com, youtube.com"
                              value={newAllowedSite}
                              onChange={(e) =>
                                setNewAllowedSite(e.target.value)
                              }
                              onKeyPress={(e) =>
                                e.key === "Enter" && addAllowedSite()
                              }
                              className="flex-1"
                            />
                            <Button onClick={addAllowedSite} size="sm">
                              <Plus className="h-4 w-4" />
                            </Button>
                          </div>

                          {contentBlocking.allowedSites.length > 0 && (
                            <div className="space-y-2 max-h-32 overflow-y-auto">
                              {contentBlocking.allowedSites.map(
                                (site, index) => (
                                  <div
                                    key={index}
                                    className="flex items-center justify-between bg-white p-2 rounded border"
                                  >
                                    <span className="text-sm">{site}</span>
                                    <Button
                                      onClick={() => removeAllowedSite(index)}
                                      size="sm"
                                      variant="ghost"
                                      className="h-6 w-6 p-0"
                                    >
                                      <X className="h-4 w-4" />
                                    </Button>
                                  </div>
                                ),
                              )}
                            </div>
                          )}
                        </div>
                      )}
                    </div>
                  </CardContent>
                </Card>

                {/* Bloqueios por Categoria */}
                {!contentBlocking.blockAllSites &&
                  !contentBlocking.allowOnlySpecific && (
                    <div className="grid md:grid-cols-2 gap-6">
                      <Card>
                        <CardHeader>
                          <CardTitle className="flex items-center gap-2 text-lg">
                            <Shield className="h-5 w-5 text-purple-600" />
                            🚫 Bloqueio de Conteúdo
                          </CardTitle>
                        </CardHeader>
                        <CardContent className="space-y-3">
                          <div className="flex items-center space-x-3">
                            <Checkbox
                              id="blockSocial"
                              checked={contentBlocking.blockCategories.social}
                              onCheckedChange={() =>
                                toggleBlockCategory("social")
                              }
                            />
                            <label
                              htmlFor="blockSocial"
                              className="text-sm font-medium cursor-pointer"
                            >
                              📱 Redes Sociais (Facebook, Instagram, TikTok,
                              Twitter...)
                            </label>
                          </div>

                          <div className="flex items-center space-x-3">
                            <Checkbox
                              id="blockGambling"
                              checked={contentBlocking.blockCategories.gambling}
                              onCheckedChange={() =>
                                toggleBlockCategory("gambling")
                              }
                            />
                            <label
                              htmlFor="blockGambling"
                              className="text-sm font-medium cursor-pointer"
                            >
                              🎰 Jogos de Aposta (Bet365, Casinos, Poker...)
                            </label>
                          </div>

                          <div className="flex items-center space-x-3">
                            <Checkbox
                              id="blockAdult"
                              checked={contentBlocking.blockCategories.adult}
                              onCheckedChange={() =>
                                toggleBlockCategory("adult")
                              }
                            />
                            <label
                              htmlFor="blockAdult"
                              className="text-sm font-medium cursor-pointer"
                            >
                              🔞 Conteúdo Adulto (Pornografia)
                            </label>
                          </div>

                          <div className="flex items-center space-x-3">
                            <Checkbox
                              id="blockGaming"
                              checked={contentBlocking.blockCategories.gaming}
                              onCheckedChange={() =>
                                toggleBlockCategory("gaming")
                              }
                            />
                            <label
                              htmlFor="blockGaming"
                              className="text-sm font-medium cursor-pointer"
                            >
                              🎮 Jogos Online (Steam, Epic Games, Valorant...)
                            </label>
                          </div>
                        </CardContent>
                      </Card>

                      <Card>
                        <CardHeader>
                          <CardTitle className="flex items-center gap-2 text-lg">
                            <Network className="h-5 w-5 text-orange-600" />
                            📺 Entretenimento
                          </CardTitle>
                        </CardHeader>
                        <CardContent className="space-y-3">
                          <div className="flex items-center space-x-3">
                            <Checkbox
                              id="blockStreaming"
                              checked={
                                contentBlocking.blockCategories.streaming
                              }
                              onCheckedChange={() =>
                                toggleBlockCategory("streaming")
                              }
                            />
                            <label
                              htmlFor="blockStreaming"
                              className="text-sm font-medium cursor-pointer"
                            >
                              📺 Streaming (Netflix, YouTube, Spotify...)
                            </label>
                          </div>

                          <div className="flex items-center space-x-3">
                            <Checkbox
                              id="blockShopping"
                              checked={contentBlocking.blockCategories.shopping}
                              onCheckedChange={() =>
                                toggleBlockCategory("shopping")
                              }
                            />
                            <label
                              htmlFor="blockShopping"
                              className="text-sm font-medium cursor-pointer"
                            >
                              🛒 Compras Online (Amazon, Mercado Livre...)
                            </label>
                          </div>

                          <div className="flex items-center space-x-3">
                            <Checkbox
                              id="blockNews"
                              checked={contentBlocking.blockCategories.news}
                              onCheckedChange={() =>
                                toggleBlockCategory("news")
                              }
                            />
                            <label
                              htmlFor="blockNews"
                              className="text-sm font-medium cursor-pointer"
                            >
                              📰 Sites de Notícias (G1, UOL, Folha...)
                            </label>
                          </div>

                          <div className="flex items-center space-x-3">
                            <Checkbox
                              id="blockEntertainment"
                              checked={
                                contentBlocking.blockCategories.entertainment
                              }
                              onCheckedChange={() =>
                                toggleBlockCategory("entertainment")
                              }
                            />
                            <label
                              htmlFor="blockEntertainment"
                              className="text-sm font-medium cursor-pointer"
                            >
                              🎭 Entretenimento (Memes, Humor, Cinema...)
                            </label>
                          </div>
                        </CardContent>
                      </Card>
                    </div>
                  )}

                {/* Firewall Básico */}
                <Card>
                  <CardHeader>
                    <CardTitle className="flex items-center gap-2 text-lg">
                      <Shield className="h-5 w-5 text-red-600" />
                      🔒 Segurança Básica
                    </CardTitle>
                  </CardHeader>
                  <CardContent className="grid md:grid-cols-2 gap-4">
                    {getRulesByCategory("security").map((rule) => (
                      <div key={rule.id} className="flex items-start space-x-3">
                        <Checkbox
                          id={rule.id}
                          checked={rule.enabled}
                          onCheckedChange={() => toggleFirewallRule(rule.id)}
                        />
                        <div className="grid gap-1.5 leading-none">
                          <label
                            htmlFor={rule.id}
                            className="text-sm font-medium leading-none cursor-pointer"
                          >
                            {rule.name}
                          </label>
                          <p className="text-xs text-gray-600">
                            {rule.description}
                          </p>
                        </div>
                      </div>
                    ))}
                  </CardContent>
                </Card>

                <div className="text-center pt-4">
                  <Button
                    onClick={() => setActiveTab("externo")}
                    className="bg-network hover:bg-network/90 text-lg px-8 py-3"
                  >
                    Próximo: Configurar Acesso Externo 🌍
                  </Button>
                </div>
              </TabsContent>

              {/* ABA ACESSO EXTERNO */}
              <TabsContent value="externo" className="p-6 space-y-6">
                <div className="text-center mb-6">
                  <h2 className="text-2xl font-bold text-purple-600 mb-2">
                    🌍 Acesso Externo
                  </h2>
                  <p className="text-gray-600">
                    Configure acesso às suas aplicações pela internet
                  </p>
                </div>

                {/* Checkbox Principal */}
                <Card className="max-w-2xl mx-auto border-2 border-purple-200">
                  <CardContent className="pt-6">
                    <div className="flex items-center space-x-3">
                      <Checkbox
                        id="enableExternalAccess"
                        checked={externalAccess.enabled}
                        onCheckedChange={(checked) =>
                          setExternalAccess({
                            ...externalAccess,
                            enabled: !!checked,
                          })
                        }
                        className="w-5 h-5"
                      />
                      <div className="grid gap-1.5 leading-none">
                        <label
                          htmlFor="enableExternalAccess"
                          className="text-lg font-semibold cursor-pointer text-purple-700"
                        >
                          🌍 Ativar Configuração de Acesso Externo
                        </label>
                        <p className="text-sm text-gray-600">
                          Marque esta opção se você deseja permitir acesso às
                          suas aplicações pela internet
                        </p>
                      </div>
                    </div>
                  </CardContent>
                </Card>

                {externalAccess.enabled && (
                  <>
                    <div className="grid md:grid-cols-2 gap-6 max-w-4xl mx-auto">
                      <Card>
                        <CardHeader>
                          <CardTitle className="flex items-center gap-2">
                            <Globe className="h-5 w-5" />
                            IP Público
                          </CardTitle>
                        </CardHeader>
                        <CardContent className="space-y-4">
                          <div className="space-y-2">
                            <Label
                              htmlFor="publicIP"
                              className="text-base font-medium"
                            >
                              🌐 IP Público do {networkConfig.providerName}
                            </Label>
                            <Input
                              id="publicIP"
                              value={externalAccess.publicIP}
                              onChange={(e) =>
                                setExternalAccess({
                                  ...externalAccess,
                                  publicIP: e.target.value,
                                })
                              }
                              placeholder="200.123.45.67"
                              className="text-base"
                            />
                            <p className="text-sm text-gray-600">
                              IP fornecido pelo {networkConfig.providerName}{" "}
                              para acesso externo
                            </p>
                          </div>
                        </CardContent>
                      </Card>

                      <Card>
                        <CardHeader>
                          <CardTitle className="flex items-center gap-2">
                            <Settings className="h-5 w-5" />
                            Configuração da Aplicação
                          </CardTitle>
                        </CardHeader>
                        <CardContent className="space-y-4">
                          <div className="space-y-2">
                            <Label
                              htmlFor="appPort"
                              className="text-base font-medium"
                            >
                              🔌 Porta da Aplicação
                            </Label>
                            <Input
                              id="appPort"
                              value={externalAccess.applicationPort}
                              onChange={(e) =>
                                setExternalAccess({
                                  ...externalAccess,
                                  applicationPort: e.target.value,
                                })
                              }
                              placeholder="80"
                              className="text-base"
                            />
                            <p className="text-sm text-gray-600">
                              Porta onde sua aplicação roda (ex: 80, 443, 8080)
                            </p>
                          </div>
                        </CardContent>
                      </Card>
                    </div>

                    <div className="max-w-2xl mx-auto">
                      <Card>
                        <CardHeader>
                          <CardTitle className="flex items-center gap-2">
                            <Shield className="h-5 w-5" />
                            Opções de Segurança
                          </CardTitle>
                        </CardHeader>
                        <CardContent className="space-y-4">
                          <div className="flex items-center space-x-3">
                            <Checkbox
                              id="enablePortForwarding"
                              checked={externalAccess.enablePortForwarding}
                              onCheckedChange={(checked) =>
                                setExternalAccess({
                                  ...externalAccess,
                                  enablePortForwarding: !!checked,
                                })
                              }
                            />
                            <div className="grid gap-1.5 leading-none">
                              <label
                                htmlFor="enablePortForwarding"
                                className="text-base font-medium cursor-pointer"
                              >
                                🔀 Habilitar Redirecionamento de Porta
                              </label>
                              <p className="text-sm text-gray-600">
                                Redireciona tráfego externo para sua aplicação
                                interna
                              </p>
                            </div>
                          </div>

                          <div className="flex items-center space-x-3">
                            <Checkbox
                              id="firewallOpen"
                              checked={externalAccess.firewallOpen}
                              onCheckedChange={(checked) =>
                                setExternalAccess({
                                  ...externalAccess,
                                  firewallOpen: !!checked,
                                })
                              }
                            />
                            <div className="grid gap-1.5 leading-none">
                              <label
                                htmlFor="firewallOpen"
                                className="text-base font-medium cursor-pointer"
                              >
                                🛡️ Abrir Porta no Firewall
                              </label>
                              <p className="text-sm text-gray-600">
                                Permite acesso externo à porta especificada
                              </p>
                            </div>
                          </div>
                        </CardContent>
                      </Card>
                    </div>
                  </>
                )}

                {!externalAccess.enabled && (
                  <Card className="max-w-2xl mx-auto bg-gray-50 border-gray-200">
                    <CardContent className="pt-6 text-center">
                      <Globe className="h-12 w-12 mx-auto mb-4 text-gray-400" />
                      <h3 className="text-lg font-semibold text-gray-600 mb-2">
                        Acesso Externo Desabilitado
                      </h3>
                      <p className="text-gray-500">
                        Marque a opção acima para configurar o acesso externo às
                        suas aplicações
                      </p>
                    </CardContent>
                  </Card>
                )}

                <div className="text-center pt-4">
                  <Button
                    onClick={() => setActiveTab("script")}
                    className="bg-purple-600 hover:bg-purple-700 text-lg px-8 py-3"
                  >
                    Gerar Script Completo 📜
                  </Button>
                </div>
              </TabsContent>

              {/* ABA GERAR SCRIPT */}
              <TabsContent value="script" className="p-6 space-y-6">
                <div className="text-center mb-6">
                  <h2 className="text-2xl font-bold text-gray-800 mb-2">
                    📜 Script Final
                  </h2>
                  <p className="text-gray-600">
                    Configuração completa para {networkConfig.providerName}
                  </p>
                </div>

                <div className="space-y-6">
                  <div className="text-center">
                    <Button
                      onClick={generateCompleteScriptWithAnimation}
                      disabled={isGenerating}
                      className="bg-gradient-to-r from-mikrotik to-network hover:from-mikrotik/90 hover:to-network/90 text-xl px-12 py-4"
                      size="lg"
                    >
                      <Code className="h-6 w-6 mr-3" />
                      {isGenerating
                        ? "🔄 Gerando..."
                        : "🚀 Gerar Configuração Completa"}
                    </Button>
                  </div>

                  {/* Terminal */}
                  {(showTerminal || generatedScript) && (
                    <Card className="shadow-lg border-2 border-gray-800">
                      <CardHeader className="bg-gray-900 text-white">
                        <div className="flex items-center justify-between">
                          <CardTitle className="flex items-center gap-2 text-green-400">
                            <Terminal className="h-5 w-5" />
                            MikroTik Terminal - {networkConfig.providerName}
                          </CardTitle>
                          <div className="flex items-center gap-2">
                            {generatedScript && !isGenerating && (
                              <>
                                <Button
                                  variant="ghost"
                                  size="sm"
                                  onClick={copyToClipboard}
                                  className="text-white hover:bg-gray-800"
                                >
                                  <Copy className="h-4 w-4 mr-1" />
                                  Copiar (Sem comentários)
                                </Button>
                                <Button
                                  variant="ghost"
                                  size="sm"
                                  onClick={downloadScript}
                                  className="text-white hover:bg-gray-800"
                                >
                                  <Download className="h-4 w-4 mr-1" />
                                  Download (Sem comentários)
                                </Button>
                              </>
                            )}
                            <Button
                              variant="ghost"
                              size="sm"
                              onClick={() => setShowTerminal(!showTerminal)}
                              className="text-white hover:bg-gray-800"
                            >
                              {showTerminal ? (
                                <EyeOff className="h-4 w-4" />
                              ) : (
                                <Eye className="h-4 w-4" />
                              )}
                              {showTerminal ? "Ocultar" : "Mostrar"}
                            </Button>
                          </div>
                        </div>
                      </CardHeader>
                      {showTerminal && (
                        <CardContent className="p-0">
                          <div
                            ref={terminalRef}
                            className="bg-black text-green-400 font-mono text-sm h-96 overflow-auto p-4 whitespace-pre-wrap scroll-smooth"
                          >
                            <div className="text-gray-500 mb-2">
                              [admin@MikroTik] {"> "}
                              <span className="text-green-400">
                                Aplicando configuração...
                              </span>
                            </div>
                            {terminalOutput}
                            {isGenerating && (
                              <div className="flex items-center gap-2 mt-2">
                                <div className="w-2 h-2 bg-green-400 rounded-full animate-pulse"></div>
                                <span className="text-green-400">
                                  Processando...
                                </span>
                              </div>
                            )}
                          </div>
                        </CardContent>
                      )}
                                        </Card>
                  )}

                  {/* Área de Cópia Manual */}
                  {showManualCopy && generatedScript && (
                    <Card className="border-2 border-orange-200 bg-orange-50">
                      <CardHeader>
                        <div className="flex items-center justify-between">
                          <CardTitle className="flex items-center gap-2 text-orange-700">
                            <Copy className="h-5 w-5" />
                            📋 Cópia Manual - Script Limpo
                          </CardTitle>
                          <Button
                            variant="ghost"
                            size="sm"
                            onClick={() => setShowManualCopy(false)}
                            className="text-orange-700 hover:bg-orange-100"
                          >
                            <X className="h-4 w-4" />
                          </Button>
                        </div>
                        <CardDescription className="text-orange-600">
                          Selecione todo o texto abaixo (Ctrl+A) e copie (Ctrl+C) para usar no MikroTik
                        </CardDescription>
                      </CardHeader>
                      <CardContent>
                        <Textarea
                          value={removeCommentsFromScript(generatedScript)}
                          readOnly
                          className="h-64 font-mono text-sm border-orange-300 focus:border-orange-500"
                          onClick={(e) => {
                            const textarea = e.target as HTMLTextAreaElement;
                            textarea.select();
                            textarea.setSelectionRange(0, 99999);
                          }}
                        />
                        <p className="text-sm text-orange-600 mt-2">
                          💡 <strong>Dica:</strong> Clique na área de texto para selecioná-la automaticamente, depois pressione Ctrl+C
                        </p>
                      </CardContent>
                    </Card>
                  )}

                  {/* Instructions */}
                  <Card className="border-l-4 border-l-green-500">
                    <CardHeader>
                      <CardTitle className="flex items-center gap-2">
                        <Play className="h-5 w-5 text-green-600" />
                        📖 Como Aplicar no MikroTik
                      </CardTitle>
                    </CardHeader>
                    <CardContent>
                      <div className="grid md:grid-cols-2 gap-6">
                        <div className="space-y-3">
                          <div className="flex items-start gap-3">
                            <div className="bg-mikrotik text-white rounded-full w-6 h-6 flex items-center justify-center text-sm font-bold">
                              1
                            </div>
                            <div>
                              <p className="font-medium">Acesse o MikroTik</p>
                              <p className="text-sm text-gray-600">
                                WinBox ou navegador (192.168.88.1)
                              </p>
                            </div>
                          </div>
                          <div className="flex items-start gap-3">
                            <div className="bg-mikrotik text-white rounded-full w-6 h-6 flex items-center justify-center text-sm font-bold">
                              2
                            </div>
                            <div>
                              <p className="font-medium">Abra o Terminal</p>
                              <p className="text-sm text-gray-600">
                                Clique em "New Terminal"
                              </p>
                            </div>
                          </div>
                        </div>
                        <div className="space-y-3">
                          <div className="flex items-start gap-3">
                            <div className="bg-network text-white rounded-full w-6 h-6 flex items-center justify-center text-sm font-bold">
                              3
                            </div>
                            <div>
                              <p className="font-medium">Cole o Script</p>
                              <p className="text-sm text-gray-600">
                                Ctrl+V no terminal (script sem comentários)
                              </p>
                            </div>
                          </div>
                          <div className="flex items-start gap-3">
                            <div className="bg-green-600 text-white rounded-full w-6 h-6 flex items-center justify-center text-sm font-bold">
                              4
                            </div>
                            <div>
                              <p className="font-medium">Pressione Enter</p>
                              <p className="text-sm text-gray-600">
                                Configuraç��o aplicada!
                              </p>
                            </div>
                          </div>
                        </div>
                      </div>
                    </CardContent>
                  </Card>
                </div>
              </TabsContent>
            </Tabs>
          </CardContent>
        </Card>
      </div>
    </div>
  );
}
