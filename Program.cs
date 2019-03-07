using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Text.RegularExpressions;
using System.Threading;
using System.Xml;
using System.Xml.Linq;
using System.Xml.Serialization;
using System.Linq;

using NCmd;
using NDesk.Options;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using System.Data.SQLite;
using Toml; // https://github.com/rossipedia/toml-net
using VDS.RDF;
using VDS.RDF.Parsing;
using VDS.RDF.Query;
using VDS.RDF.Query.Datasets;
using VDS.RDF.Storage;
using VDS.RDF.Update;
using VDS.RDF.Writing;
using VDS.RDF.Writing.Formatting;


namespace ObsidianSailboat
{
    public class NseWriter {
        public void WriteColor(ConsoleColor color, string arg) {
            Console.ForegroundColor = color;
            Console.WriteLine(arg);
            Console.ResetColor();
        }
        public void OK(string arg) {
            WriteColor(ConsoleColor.Green, "[+] " + arg);
        }

        public void Warn(string arg) {
            WriteColor(ConsoleColor.Yellow, "[-] " + arg);
        }

        public void Error(string arg) {
            WriteColor(ConsoleColor.Red, "[!] " + arg);
        }

        public void Info(string arg) {
            WriteColor(ConsoleColor.Blue, "[*] " + arg);
        }
    }

    class NseShell : Cmd {

        public Dictionary<string, NmapOption> global_options;
        public Dictionary<string, Nmap> modules;
        public Nmap handler;
        private NseWriter nw;
        private string nmap_path;
        private string nse_dir;
        public Graph graph;
        private string workspace;
        private string graph_file;
        private Dictionary<string, string> vuln_cache;

        public NseShell(string nmap_path, string nse_dir, string workspace) {
            this.nmap_path = nmap_path;
            this.nse_dir = nse_dir;
            CommandPrompt = "osail > ";
            this.modules = new Dictionary<string, Nmap>();
            this.handler = new Nmap(this.nmap_path);
            this.nw = new NseWriter();
            this.BuildModules();
            this.global_options = new Dictionary<string, NmapOption>();
            this.global_options.Add("--exclude", new NmapOption("", "Exclude hosts/networks"));
            this.global_options.Add("--excludefile", new NmapOption("", "Exclude list from file"));
            this.global_options.Add("--exclude-ports", new NmapOption("", "Exclude the specified ports from scanning"));
            this.global_options.Add("--scan-delay", new NmapOption("", "Adjust delay between probes"));
            this.graph = new Graph(); 
            this.graph.NamespaceMap.AddNamespace("net", new Uri("http://example.com/schema/1/net#"));
            this.graph.NamespaceMap.AddNamespace("vuln", new Uri("http://example.com/schema/1/vuln#"));
            this.graph.NamespaceMap.AddNamespace("exploit", new Uri("http://example.com/schema/1/exploit#"));
            this.graph.NamespaceMap.AddNamespace("cvss", new Uri("http://example.com/schema/1/cvss#"));
            this.graph.NamespaceMap.AddNamespace("rdf", new Uri("http://www.w3.org/1999/02/22-rdf-syntax-ns#"));
            this.Use_Workspace(workspace);
            this.vuln_cache = new Dictionary<string, string>();
        }

        private void Add_Workspace(string workspace) {
            var homedir = Environment.GetEnvironmentVariable("HOME");
            if (Directory.Exists($"{homedir}/.osail/workspaces/{workspace}")) {
                this.nw.Error(String.Format($"Workspace {workspace} exists, not continuing"));
                return;
            }
            Directory.CreateDirectory($"{homedir}/.osail/workspaces/{workspace}");
            File.Copy($"{homedir}/.osail/data/blank_graph.rdf", $"{homedir}/.osail/workspaces/{workspace}/graph.rdf");
            this.nw.Info($"Workspace {workspace} added");
        }

        private void Use_Workspace(string workspace) {
            var homedir = Environment.GetEnvironmentVariable("HOME");
            if (Directory.Exists($"{homedir}/.osail/workspaces/{workspace}") == false) {
                this.nw.Error(String.Format($"Workspace {workspace} not found, not changing"));
                return;
            }
            this.workspace = workspace;
            this.graph_file = $"{homedir}/.osail/workspaces/{workspace}/graph.rdf";
            this.graph.Clear();
            try {
                FileLoader.Load(this.graph, this.graph_file);
                this.nw.Info($"workspace => {workspace}");
            }
            catch {
                if (workspace == "default") {
                    this.nw.Error($"Workspace {workspace} broken, giving up.");
                    System.Environment.Exit(1);
                }
                this.nw.Equals($"Broken workspace: {workspace}, reverting to default");
                this.Use_Workspace("default");
            }
            return;
        }

        public List<string> Get_Hosts() {
            var hosts = new List<string>();
            SparqlQueryParser parser = new SparqlQueryParser();
            string query = @"PREFIX net: <http://example.com/schema/1/net#> 
    PREFIX vuln:  <http://example.com/schema/1/vuln#>
    PREFIX exploit:  <http://example.com/schema/1/exploit#>
    PREFIX cvss: <http://example.com/schema/1/cvss#>
    PREFIX rdf: <http://www.w3.org/1999/02/22-rdf-syntax-ns#> 

    SELECT DISTINCT 
        ?i 
    WHERE { ?h rdf:type net:IP . 
            ?h net:hasIp ?i  . 
    }";
            SparqlQuery q = parser.ParseFromString(query);            
            SparqlResultSet results = this.graph.ExecuteQuery(q) as SparqlResultSet;
            for (int i = 0; i < results.Count; i++) {
                hosts.Add(results[i]["i"].ToString());
            }
            return hosts;
        }

        private void BuildModules() {
            this.nw.Info("Building modules ...");
	    foreach (string nse_dir in this.nse_dir.Split(',')) {
                var files = Directory.GetFiles(nse_dir, "*.nse");
                foreach (string file in files) {
                    Nmap nse = new Nmap(this.nmap_path, file);
		    if (Array.IndexOf(nse.categories, "external") > -1) {
			this.nw.Info("found an external script");
			nse.flags.Add("-sn");
			nse.flags.Add("-Pn");
			nse.flags.Add("-n");
			nse.args.Remove("RPORT");
		    }
                    foreach (string name in nse.Name_Branch()) {
                        this.nw.Info($"Adding {file} as {name}");
                        this.modules.Add(name, nse);
                    } 
		}
            }
            this.nw.Info("Done.");
        }

        // https://stackoverflow.com/questions/5008423/pythons-xml-etree-getiterator-equivalent-to-c-sharp
        private void Parse_Nmap_XML(string xml) {
            var homedir = Environment.GetEnvironmentVariable("HOME");
            var now = System.DateTime.UtcNow.Ticks.ToString();
            var path = $"{homedir}/.osail/workspaces/{workspace}/{now}.xml";
            File.WriteAllText(path, xml);
            XDocument nmap_xml = XDocument.Parse(xml);

            INode rdfType = this.graph.CreateUriNode("rdf:type");
            INode netIp = this.graph.CreateUriNode("net:IP");
            INode nethasIp = this.graph.CreateUriNode("net:hasIp");
            INode netHostname = this.graph.CreateUriNode("net:hasHostname");
            INode netdnsname = this.graph.CreateUriNode("net:hasDnsName");
            INode netdnstype = this.graph.CreateUriNode("net:hasDnsType");
            INode netHasPort = this.graph.CreateUriNode("net:hasPort");

            INode netPort = this.graph.CreateUriNode("net:Port");
            INode netHasNumber = this.graph.CreateUriNode("net:hasNumber");
            INode netHasProtocol = this.graph.CreateUriNode("net:hasProtocol");
            INode netHasState = this.graph.CreateUriNode("net:hasState");
            INode netHasReason = this.graph.CreateUriNode("net:hasReason");
            INode netHasServiceName = this.graph.CreateUriNode("net:hasServiceName");
            INode netHasProduct = this.graph.CreateUriNode("net:hasProduct");
            INode netHasCpe = this.graph.CreateUriNode("net:hasCPE");

            INode netFinding = this.graph.CreateUriNode("net:Finding");
            INode netHasScript = this.graph.CreateUriNode("net:hasScript");
            INode netHasOutput = this.graph.CreateUriNode("net:hasOutput");

            INode netHasFinding = this.graph.CreateUriNode("net:hasFinding");

            // Console.WriteLine("Graph has {0} triples", this.graph.Triples.Count);
            foreach (var host in nmap_xml.Root.Elements("host")) {
                var address = host.Element("address");
                string ip = address.Attribute("addr").Value;
                this.nw.Info(ip);
                var thishost = this.Get_One(nethasIp, ip); //  this.graph.CreateBlankNode();
                this.Add_Triple(thishost, rdfType, netIp);
                this.Add_Triple(thishost, nethasIp, this.graph.CreateLiteralNode(ip));
                foreach (var H in host.Elements("hostnames")) {
                    foreach (var hostname in H.Elements("hostname")) {
                        string name = hostname.Attribute("name").Value;
                        string dnstype = hostname.Attribute("type").Value;
                        var thishostname = this.graph.CreateBlankNode();
                        this.Add_Triple(thishost, netHostname, thishostname);
                        this.Add_Triple(thishostname, netdnsname, this.graph.CreateLiteralNode(name));
                        this.Add_Triple(thishostname, netdnstype, this.graph.CreateLiteralNode(dnstype));
                    }
                }
                foreach (var P in host.Elements("ports")) {
                    foreach (var port in P.Elements("port")) {
                        string portnum = port.Attribute("portid").Value;
                        string proto = port.Attribute("protocol").Value;
                        var thisport =  this.Get_One(netHasNumber, portnum); // graph.CreateBlankNode();
                        this.Add_Triple(thisport, rdfType, netPort);
                        this.Add_Triple(thisport, netHasNumber, graph.CreateLiteralNode(portnum));
                        this.Add_Triple(thisport, netHasProtocol, graph.CreateLiteralNode(proto));
                        foreach (var state in port.Elements("state")) {
                            this.Add_Triple(thisport, netHasState, graph.CreateLiteralNode(state.Attribute("state").Value));
                        }
                        foreach (var service in port.Elements("service")) {
                            this.Add_Triple(thisport, netHasServiceName, graph.CreateLiteralNode(service.Attribute("name").Value));
                            try {
                                string product = "";
                                string version = "";
                                try {product = service.Attribute("product").Value;}
                                catch (System.ArgumentNullException) {product = "";}
                                catch (System.NullReferenceException) {product = "";}
                                try {version = service.Attribute("version").Value;}
                                catch (System.ArgumentNullException) {version = "";}
                                catch (System.NullReferenceException) {version = "";}
                                this.Add_Triple(thisport, netHasProduct, graph.CreateLiteralNode(product + " " + version));
                                string key = String.Format($"{product}-{version.Split(" ").First()}");
                                if (vuln_cache.ContainsKey(key)) {
                                    // pass
                                } else {
                                    // https://github.com/vulnersCom/nmap-vulners/blob/master/vulners.nse#L72
                                    string vulnersquery = String.Format($"http://vulners.com/api/v3/burp/software/?software={product}&type=cpe&version={version.Split(" ").First()}");
                                    var wc = new WebClient();
                                    string json = wc.DownloadString(vulnersquery);
                                    this.vuln_cache.Add(key, json);
                                    List<string> cvelist = Parse_Vulners_Software_Json(json, thisport);
                                    foreach (string cve in cvelist) {
                                        if (vuln_cache.ContainsKey(cve)) {
                                            continue;
                                        }
                                        string cvequery = String.Format($"https://vulners.com/api/v3/search/id/?id={cve}&references=true");
                                        json = wc.DownloadString(cvequery);
                                        this.vuln_cache.Add(key, json);                                        
                                        Parse_Vulners_Exploit_Json(json, thisport);
                                        vuln_cache.Add(cve, json);
                                    }
                                }
                            }
                            catch (Exception e)  {
                                this.nw.Warn($"Exception seen: {e}");
                            }
                            foreach (var cpe in service.Elements("cpe")) {
                                this.Add_Triple(thisport, netHasCpe, graph.CreateLiteralNode(cpe.Value));
                            }
                        }
                        foreach (var script in port.Elements("script")) {
                            var thisfinding = this.graph.CreateBlankNode();
                            this.Add_Triple(thisfinding, rdfType, netFinding);
                            this.Add_Triple(thisfinding, netHasScript, this.graph.CreateLiteralNode(script.Attribute("id").Value));
                            foreach (var table in script.Elements("table")) {
                                foreach (var elem in table.Elements("elem")) {
                                    this.Add_Triple(thisfinding, netHasOutput, this.graph.CreateLiteralNode(elem.Value));
                                }
                            }
                            foreach (var elem in script.Elements("elem")) {
                                string value = elem.Value;
                                string key = "";
                                try {
                                    key = elem.Attribute("key").Value;
                                } 
                                catch {
                                    //Console.WriteLine("no key");
                                }
                                if (key.Length > 0) {
                                    key = key + "=";
                                }
                                this.Add_Triple(thisfinding, netHasOutput, this.graph.CreateLiteralNode(key + value));
                            }
                            string output = script.Attribute("output").Value;
                            this.Add_Triple(thisfinding, netHasOutput, this.graph.CreateLiteralNode(output));
                            this.nw.Info(output);
                            this.Add_Triple(thishost, netHasFinding, thisfinding);
                        }
                        this.Add_Triple(thishost, netHasPort, thisport);
                    }
                }
                foreach (var script in host.Elements("script")) {
                    var thisfinding = this.graph.CreateBlankNode();
                    this.Add_Triple(thisfinding, rdfType, netFinding);
                    this.Add_Triple(thisfinding, netHasScript, this.graph.CreateLiteralNode(script.Attribute("id").Value));
                    foreach (var table in script.Elements("table")) {
                        foreach (var elem in table.Elements("elem")) {
                            this.Add_Triple(thisfinding, netHasOutput, this.graph.CreateLiteralNode(elem.Value));
                        }
                    }
                    this.Add_Triple(thishost, netHasFinding, thisfinding);
                }
            }
	    try {
                this.nw.Info(nmap_xml.Root.Element("runstats").Element("finished").Attribute("summary").Value);
	    }
	    catch {
		// Masscan doesn't quite do Nmap XML run for runstats
		this.nw.Info("Completed, took " + nmap_xml.Root.Element("runstats").Element("finished").Attribute("elapsed").Value + " seconds");
	    }
            // https://bitbucket.org/dotnetrdf/dotnetrdf/wiki/UserGuide/Writing%20RDF
            RdfXmlWriter rdfxmlwriter = new RdfXmlWriter();
            rdfxmlwriter.Save(this.graph, this.graph_file);
            // http://www.dotnetrdf.org/api/html/T_VDS_RDF_Writing_CompressingTurtleWriter.htm
            CompressingTurtleWriter ttlwriter = new CompressingTurtleWriter();
            ttlwriter.Save(this.graph, this.graph_file.Replace(".rdf", ".ttl"));
        }

        private void Add_Triple(INode s, INode p, INode o) {
            this.graph.Assert(new Triple(s,p,o));
        }

        private INode Get_One(INode predicate, string value) {
            string predstring = predicate.ToString();
            SparqlQueryParser parser = new SparqlQueryParser();
            string query = $@"PREFIX net: <http://example.com/schema/1/net#> 
    PREFIX vuln:  <http://example.com/schema/1/vuln#>
    PREFIX exploit:  <http://example.com/schema/1/exploit#>
    PREFIX cvss: <http://example.com/schema/1/cvss#>
    PREFIX rdf: <http://www.w3.org/1999/02/22-rdf-syntax-ns#> 
    
    SELECT DISTINCT ?x WHERE {{ ?x ""{predstring}"" ""{value}"" }} ";
            SparqlQuery q = parser.ParseFromString(query);    
            SparqlResultSet results = this.graph.ExecuteQuery(q) as SparqlResultSet;
            if (results.Count > 0) {
                return this.graph.CreateLiteralNode(results[0]["x"].ToString());
            } 
            return this.graph.CreateBlankNode();
        }

        private void Parse_Vulners_Exploit_Json(string json, INode thisport) {
            INode vulnHasCvss = this.graph.CreateUriNode("vuln:hasCvss");
            INode cvssScore = this.graph.CreateUriNode("cvss:score");
            INode cvssVector = this.graph.CreateUriNode("cvss:vector");

            INode netHasExploit = this.graph.CreateUriNode("net:hasExploit");
            INode exploitDescription = this.graph.CreateUriNode("exploit:description");
            INode exploitType = this.graph.CreateUriNode("exploit:type");
            INode exploitId = this.graph.CreateUriNode("exploit:id");
            
            JObject vulners = JObject.Parse(json);
            if ((string)vulners["result"] != "OK") {
                return;
            }
            JArray references = (JArray)vulners["data"]["references"];
            foreach (var result in references) {
                if ((string)result["type"] == "exploitdb") {
                    string type = "exploit";
                    string expid = (string)result["ID"];
                    nw.Info($"  {expid}");
                    string description = (string)result["description"];
                    string cvss_score = (string)result["cvss"]["score"];
                    string cvss_vector = (string)result["cvss"]["vector"];
                    var thisexp = this.Get_One(exploitId, expid);
                    this.Add_Triple(thisexp, exploitDescription, this.graph.CreateLiteralNode(description));
                    this.Add_Triple(thisexp, exploitType, this.graph.CreateLiteralNode(type));
                    this.Add_Triple(thisexp, exploitId, this.graph.CreateLiteralNode(expid));
                    this.Add_Triple(thisport, netHasExploit, thisexp);
                    var thiscvss = this.graph.CreateBlankNode($"{cvss_score}-{cvss_vector}");
                    this.Add_Triple(thiscvss, cvssScore, this.graph.CreateLiteralNode(cvss_score));
                    this.Add_Triple(thiscvss, cvssVector, this.graph.CreateLiteralNode(cvss_vector));
                }
            }
        }

        private List<string> Parse_Vulners_Software_Json(string json, INode thisport) {
            List<string> cvelist = new List<string>();

            INode netHasVulnerability = this.graph.CreateUriNode("net:hasVulnerability");
            INode vulnDescription = this.graph.CreateUriNode("vuln:description");
            INode vulnType = this.graph.CreateUriNode("vuln:type");
            INode vulnId = this.graph.CreateUriNode("vuln:id");

            INode netHasExploit = this.graph.CreateUriNode("net:hasExploit");
            INode exploitDescription = this.graph.CreateUriNode("exploit:description");
            INode exploitType = this.graph.CreateUriNode("exploit:type");
            INode exploitId = this.graph.CreateUriNode("exploit:id");

            INode vulnHasCvss = this.graph.CreateUriNode("vuln:hasCvss");
            INode cvssScore = this.graph.CreateUriNode("cvss:score");
            INode cvssVector = this.graph.CreateUriNode("cvss:vector");

            // https://www.newtonsoft.com/json/help/html/QueryingLINQtoJSON.htm
            JObject vulners = JObject.Parse(json);
            if ((string)vulners["result"] != "OK") {
                return cvelist;
            }
            JArray results = (JArray)vulners["data"]["search"];
            foreach (var result in results) {
                if ((string)result["type"] == "cve") {
                    string type = "cve";
                    string cve = (string)result["ID"];
                    cvelist.Add(cve);
                    nw.Info($"  {cve}");
                    string description = (string)results["description"];
                    string cvss_score = (string)result["cvss"]["score"];
                    string cvss_vector = (string)result["cvss"]["vector"];
                    var thisvuln = this.Get_One(vulnId, cve); //  this.graph.CreateBlankNode();
                    this.Add_Triple(thisvuln, vulnDescription, this.graph.CreateLiteralNode(description));
                    this.Add_Triple(thisvuln, vulnType, this.graph.CreateLiteralNode(type));
                    this.Add_Triple(thisvuln, vulnId, this.graph.CreateLiteralNode(cve));
                    this.Add_Triple(thisport, netHasVulnerability, thisvuln);
                    var thiscvss = this.graph.CreateBlankNode($"{cvss_score}-{cvss_vector}");
                    this.Add_Triple(thiscvss, cvssScore, this.graph.CreateLiteralNode(cvss_score));
                    this.Add_Triple(thiscvss, cvssVector, this.graph.CreateLiteralNode(cvss_vector));
                    this.Add_Triple(thisvuln, vulnHasCvss, thiscvss);
                } else {
                    Console.WriteLine((string)result["type"]);
                }
            }
            return cvelist;
        }

        private void Show_Results(string module_name) {
            SparqlQueryParser parser = new SparqlQueryParser();
            SparqlParameterizedString queryString = new SparqlParameterizedString();
            queryString.CommandText = $@"PREFIX net: <http://example.com/schema/1/net#>
    PREFIX vuln:  <http://example.com/schema/1/vuln#>
    PREFIX exploit:  <http://example.com/schema/1/exploit#>
    PREFIX cvss: <http://example.com/schema/1/cvss#>
    PREFIX rdf: <http://www.w3.org/1999/02/22-rdf-syntax-ns#> 
    
    SELECT DISTINCT ?ip ?port ?proto ?svc ?output
    WHERE {{ 
        ?x rdf:type net:IP  . 
        ?x net:hasIp ?ip . 
        ?y rdf:type net:Port .
        ?x net:hasPort ?y .
        ?y net:hasNumber ?port .
        ?y net:hasProtocol ?proto .        
        ?x net:hasFinding ?f .
        ?f rdf:type net:Finding .
        ?f net:hasOutput ?output . 
        ?f net:hasScript @script .
        ?y net:hasServiceName ?svc
    }} ";
            queryString.SetLiteral("script", module_name.Trim());
            SparqlQuery q = parser.ParseFromString(queryString);            
            SparqlResultSet results = this.graph.ExecuteQuery(q) as SparqlResultSet;
            var rows = new List<SparqlResult>();
            for (int i = 0; i < results.Count; i++) {
                rows.Add(results[i]);
            }
            var res = new List<string>();
            res.Add(String.Format("{0,-20} {1,-8} {2,-7} {3,-12} {4}", "IP", "Proto", "Port", "Service", "Output"));
            res.Add(String.Format("{0,-20} {1,-8} {2,-7} {3,-12} {4}", "--", "-----", "----", "-------", "------"));
            foreach (var row in rows) {
                res.Add(String.Format("{0,-20} {1,-8} {2,-7} {3,-12} {4}", 
                                        row.Value("ip").ToString(), 
                                        row.Value("proto").ToString(), 
                                        row.Value("port").ToString(), 
                                        row.Value("svc").ToString(), 
                                        row.Value("output").ToString().TrimStart()));
            }
            Console.WriteLine(String.Join("\n", res) + "\n");
        }

        private void Show_Vulns() {
            var exp_mods = new HashSet<string>();
            foreach (KeyValuePair<string, Nmap> kv in this.modules) {                
                if (kv.Key.StartsWith("vuln") || kv.Key.StartsWith("expl")) {
                    exp_mods.Add(kv.Value.name);
                }
            }
            var rows = new List<SparqlResult>();
            SparqlQueryParser parser = new SparqlQueryParser();
            SparqlParameterizedString queryString = new SparqlParameterizedString();
            foreach (string module_name in exp_mods) {
                queryString.CommandText = $@"PREFIX net: <http://example.com/schema/1/net#>
    PREFIX vuln:  <http://example.com/schema/1/vuln#>
    PREFIX exploit:  <http://example.com/schema/1/exploit#>
    PREFIX cvss: <http://example.com/schema/1/cvss#>
    PREFIX rdf: <http://www.w3.org/1999/02/22-rdf-syntax-ns#> 
    
    SELECT DISTINCT ?ip ?port ?proto ?svc ?script
    WHERE {{ 
        ?x rdf:type net:IP  . 
        ?x net:hasIp ?ip . 
        ?y rdf:type net:Port .
        ?x net:hasPort ?y .
        ?y net:hasNumber ?port .
        ?y net:hasProtocol ?proto .        
        ?x net:hasFinding ?f .
        ?f rdf:type net:Finding .
        ?f net:hasScript @script .
        ?f net:hasScript ?script .
        ?y net:hasServiceName ?svc
    }} ";
                queryString.SetLiteral("script", module_name.Trim());
                SparqlQuery q = parser.ParseFromString(queryString);            
                SparqlResultSet results = this.graph.ExecuteQuery(q) as SparqlResultSet;
                for (int i = 0; i < results.Count; i++) {
                    rows.Add(results[i]);
                }
            }
            var res = new List<string>();
            res.Add(String.Format("{0,-20} {1,-8} {2,-7} {3,-12} {4}", "IP", "Proto", "Port", "Service", "Script"));
            res.Add(String.Format("{0,-20} {1,-8} {2,-7} {3,-12} {4}", "--", "-----", "----", "-------", "------"));
            foreach (var row in rows) {
                res.Add(String.Format("{0,-20} {1,-8} {2,-7} {3,-12} {4}", 
                                        row.Value("ip").ToString(), 
                                        row.Value("proto").ToString(), 
                                        row.Value("port").ToString(), 
                                        row.Value("svc").ToString(), 
                                        row.Value("script").ToString()));
            }
            Console.WriteLine(String.Join("\n", res) + "\n");
            return;
        }

        // TODO
        // FIX rescan to include static modules/built in functionality
        // FIX detail without name - no IP returned if no hostname found (query)
        // ADD migrate from XML to TTL graph format
        // ADD parse references
        // ADD search hosts by CPE, software, name, etc https://www.ibm.com/developerworks/library/j-sparql/
        // ADD search hosts-service by CVSS - "find me a shell on these hosts"
        // ADD iflist, routes (--iflist, then parse)
        // ADD scan through tor https://www.aldeid.com/wiki/Tor/Usage/Nmap-scan-through-tor 
        // ADD export

        // IN PROGRESS
        // ADD vulners integration - search API by CPE
        // ADD check vulners for exploits

        // MAYBE
        // ADD ncrack support?

        [CmdCommand(Command = "add",
                    Description = "Add a host by IP or hostname")]
        public void Add(string arg) {
            IPAddress[] addrlist = new IPAddress[]{};
            var ips = new List<string>();
            string name = arg;
            IPAddress address;
            if (IPAddress.TryParse(arg, out address)) {
                ips.Add(address.ToString());
                name = "";
            } else {
                try {
                    IPHostEntry hostEntry = Dns.GetHostEntry(arg);
                    foreach (var addr in hostEntry.AddressList) {
                        ips.Add(addr.ToString());
                    }
                } 
                catch {
                    this.nw.Error($"No such host {arg}");
                    return;
                }
            }
            // https://docs.microsoft.com/en-us/dotnet/csharp/programming-guide/concepts/linq/creating-xml-trees-linq-to-xml-2
            foreach (var ip in ips) {
                XElement host = new XElement("nmaprun",
                                  new XElement("host", 
                                    new XElement("address", new XAttribute("addr", ip)),
                                    new XElement("hostnames",
                                      new XElement("hostname", new XAttribute("name", name), new XAttribute("type", "A")))
                                    ),
                                new XElement("runstats", 
                                  new XElement("finished", new XAttribute("summary", "Added 1 host")))
                );
                this.Parse_Nmap_XML(host.ToString());
            }
        }

        [CmdCommand(Command = "back",
                    Description = "Return to the top level command")]
        public void Back(string arg) {
            CommandPrompt = "osail > ";
            this.handler = new Nmap(this.nmap_path);
        }

        [CmdCommand(Command = "banner", 
                    Description = "Prints a random OSail banner")]
        public void Banner(string arg) {
            var rand = new Random();
            var files = Directory.GetFiles("banners");
            string banner = File.ReadAllText(files[rand.Next(files.Length)]);
            Console.Write(banner);
        }

        [CmdCommand(Command = "detail",
                    Description = "Get detailed info about a host")]
        public void HostDetail(string arg) {
            arg = arg.Trim();
            SparqlQueryParser parser = new SparqlQueryParser();
            // http://www.dotnetrdf.org/api/html/T_VDS_RDF_Query_SparqlParameterizedString.htm
            SparqlParameterizedString queryString = new SparqlParameterizedString();
            queryString.CommandText = $@"PREFIX net: <http://example.com/schema/1/net#>
    PREFIX vuln:  <http://example.com/schema/1/vuln#>
    PREFIX exploit:  <http://example.com/schema/1/exploit#>
    PREFIX cvss: <http://example.com/schema/1/cvss#>
    PREFIX rdf: <http://www.w3.org/1999/02/22-rdf-syntax-ns#> 
    
    SELECT DISTINCT ?port ?svc ?proto ?state ?cpe
    WHERE {{ 
        ?x rdf:type net:IP  . 
        ?x net:hasIp @ip . 
        ?y rdf:type net:Port .
        ?x net:hasPort ?y .
        ?y net:hasNumber ?port .
        ?y net:hasProtocol ?proto .        
        ?y net:hasState ?state .
    OPTIONAL {{ ?y net:hasCPE ?cpe . 
                ?y net:hasServiceName ?svc }}
    }} ";
            queryString.SetLiteral("ip", arg.Trim());
            SparqlQuery q = parser.ParseFromString(queryString);            
            SparqlResultSet results = this.graph.ExecuteQuery(q) as SparqlResultSet;
            var rows = new List<SparqlResult>();
            for (int i = 0; i < results.Count; i++) {
                rows.Add(results[i]);
            }

            parser = new SparqlQueryParser();
            queryString.CommandText = $@"PREFIX net: <http://example.com/schema/1/net#> 
    PREFIX vuln:  <http://example.com/schema/1/vuln#>
    PREFIX exploit:  <http://example.com/schema/1/exploit#>
    PREFIX cvss: <http://example.com/schema/1/cvss#>
    PREFIX rdf: <http://www.w3.org/1999/02/22-rdf-syntax-ns#> 
    
    SELECT DISTINCT ?name WHERE {{ ?x rdf:type net:IP  . ?x net:hasIp @ip . ?x net:hasHostname ?hn . ?hn net:hasDnsName ?name  }} ";
            queryString.SetLiteral("ip", arg.Trim());
            q = parser.ParseFromString(queryString);            
            results = this.graph.ExecuteQuery(q) as SparqlResultSet;
            var names = new List<string>();
            for (int i = 0; i < results.Count; i++) {
                names.Add(results[i].Value("name").ToString());
            }

            queryString.CommandText = $@"PREFIX net: <http://example.com/schema/1/net#> 
    PREFIX vuln:  <http://example.com/schema/1/vuln#>
    PREFIX exploit:  <http://example.com/schema/1/exploit#>
    PREFIX cvss: <http://example.com/schema/1/cvss#>
    PREFIX rdf: <http://www.w3.org/1999/02/22-rdf-syntax-ns#> 
    
    SELECT DISTINCT ?port ?proto ?output ?script 
        WHERE {{ ?x rdf:type net:IP  . 
                ?x net:hasIp @ip . 
                ?y rdf:type net:Port .
                ?x net:hasPort ?y .
                ?y net:hasNumber ?port .
                ?y net:hasProtocol ?proto .
        OPTIONAL  {{
            ?y net:hasFinding ?f .
            ?f rdf:type net:Finding .
            ?f net:hasOutput ?output . 
            ?f net:hasScript ?script
            }}
        }} ";
            queryString.SetLiteral("ip", arg.Trim());
            q = parser.ParseFromString(queryString);            
            results = this.graph.ExecuteQuery(q) as SparqlResultSet;
            var portscripts = new List<SparqlResult>();
            for (int i = 0; i < results.Count; i++) {
                portscripts.Add(results[i]);
            }

            queryString.CommandText = $@"PREFIX net: <http://example.com/schema/1/net#> 
    PREFIX vuln:  <http://example.com/schema/1/vuln#>
    PREFIX exploit:  <http://example.com/schema/1/exploit#>
    PREFIX cvss: <http://example.com/schema/1/cvss#>
    PREFIX rdf: <http://www.w3.org/1999/02/22-rdf-syntax-ns#> 
    
    SELECT DISTINCT ?hostscript ?hostoutput 
        WHERE {{ ?x rdf:type net:IP  . 
                ?x net:hasIp @ip . 
                ?x net:hasFinding ?hf .
                ?hf net:hasScript ?hostscript .
                ?hf net:hasOutput ?hostoutput 
        }} ";
            queryString.SetLiteral("ip", arg.Trim());
            q = parser.ParseFromString(queryString);            
            results = this.graph.ExecuteQuery(q) as SparqlResultSet;
            var hostscripts = new List<SparqlResult>();
            for (int i = 0; i < results.Count; i++) {
                hostscripts.Add(results[i]);
            }

            var nametable = new List<string>();
            string ip = arg;
            nametable.Add(String.Format("  {0,-20}{1}", "Host", "Name"));
            nametable.Add(String.Format("  {0,-20}{1}", "----", "----"));
            foreach (var line in names) {
                nametable.Add(String.Format("  {0,-20}{1}", ip, line));
                ip = "";
            }
            Console.WriteLine(String.Join("\n", nametable) + "\n");

            var porttable = new List<string>();
            porttable.Add(String.Format("  {0,-8} {1,-7} {2,-12} {3,-14} {4}", "Proto", "Port", "State", "Service", "CPE"));
            porttable.Add(String.Format("  {0,-8} {1,-7} {2,-12} {3,-14} {4}", "-----", "----", "-----", "-------", "---"));
            foreach (var row in rows) {
                //  ?port ?svc ?proto ?state ?cpe 
                string cpe = "";
                try {
                    cpe = row.Value("cpe").ToString();
                }
                catch { }
                string svc = "";
                try {
                    svc = row.Value("svc").ToString();
                }
                catch { } 
                porttable.Add(String.Format("  {0,-8} {1,-7} {2,-12} {3,-14} {4}", row.Value("proto").ToString(), 
                                                                                   row.Value("port").ToString(), 
                                                                                   row.Value("state").ToString(), 
                                                                                   svc, 
                                                                                   cpe));
            }
            Console.WriteLine(String.Join("\n", porttable) + "\n");

            // ?port ?proto ?output ?script 
            var portscripttable = new List<string>();
            portscripttable.Add(String.Format("  {0,-8} {1,-6} {2,-20} {3}", "Port", "Proto", "Script", "Output"));
            portscripttable.Add(String.Format("  {0,-8} {1,-6} {2,-20} {3}", "----", "-----", "------", "------"));
            foreach (var row in portscripts) {
                string script = "";
                try {
                    script = row.Value("script").ToString();
                }
                catch { }
                string output = "";
                try {
                    output = row.Value("output").ToString();
                }
                catch { }
                portscripttable.Add(String.Format("  {0,-8} {1,-6} {2,-20} {3}", row.Value("port").ToString(),
                                                              row.Value("proto").ToString(),
                                                              script,
                                                              output));  
            }
            Console.WriteLine(String.Join("\n", portscripttable) + "\n");

            // ?hostscript ?hostoutput 
            var scripttable = new List<string>();
            scripttable.Add(String.Format("  {0,-25} {1}", "Script", "Output"));
            scripttable.Add(String.Format("  {0,-25} {1}", "------", "------"));
            foreach (var row in hostscripts) {
                scripttable.Add(String.Format("  {0,-25} {1}", row.Value("hostscript").ToString(), row.Value("hostoutput").ToString()));
            }
            Console.WriteLine(String.Join("\n", scripttable) + "\n");
        }

        [CmdCommand(Command = "exit",
                    Description = "Exits OSail")]
        public void Exit(string arg) {
            ExitLoop();
        }

        [CmdCommand(Command = "getf",
                    Description = "Get the module's Nmap flags")]
        public void Get_Flags(string unused) {
            this.nw.Info(String.Join(" ", this.handler.flags));
        }

        [CmdCommand(Command = "getg",
                    Description = "Get global option information")]
        public void Get_Global(string arg) {
            var res = new List<string>();
            res.Add("Options:");
            res.Add(String.Format("  {0,-40}{1,-20}{2}", "Name", "Current Setting", "Description"));
            res.Add(String.Format("  {0,-40}{1,-20}{2}", "----", "---------------", "-----------"));
            string row;
            if (arg.Length > 0) {
                if (this.global_options.ContainsKey(arg)) {
                    var go = this.global_options[arg];
                    row = String.Format("  {0,-40}{1,-20}{2}", arg, go.oval, go.odesc);
                    res.Add(row);
                } else {
                    this.nw.Warn($"No such option {arg}");
                    return;
                }
            } else {
                    foreach (KeyValuePair<string, NmapOption> kv in this.global_options) {                
                        row = String.Format("  {0,-40}{1,-20}{2}", kv.Key, kv.Value.oval, kv.Value.odesc);
                        res.Add(row);
                    }
                }
            Console.WriteLine(String.Join('\n', res));
        }

        [CmdCommand(Command = "hosts",
                    Description = "Show info about known hosts")]
        public void Hosts(string arg) {
            SparqlQueryParser parser = new SparqlQueryParser();
            string query = @"PREFIX net: <http://example.com/schema/1/net#> 
    PREFIX vuln:  <http://example.com/schema/1/vuln#>
    PREFIX exploit:  <http://example.com/schema/1/exploit#>
    PREFIX cvss: <http://example.com/schema/1/cvss#>
    PREFIX rdf: <http://www.w3.org/1999/02/22-rdf-syntax-ns#> 
    
    SELECT DISTINCT 
        ?i ?name 
    WHERE { ?h rdf:type net:IP . 
            ?h net:hasIp ?i  . 
    OPTIONAL { ?h net:hasHostname ?hn . 
                ?hn net:hasDnsName ?name 
                } 
    }";
            SparqlQuery q = parser.ParseFromString(query);            
            SparqlResultSet results = this.graph.ExecuteQuery(q) as SparqlResultSet;
            nw.Info($"Found {results.Count} Hosts");
            var res = new List<string>();
            res.Add(String.Format("  {0,-20}{1}", "Host", "Name"));
            res.Add(String.Format("  {0,-20}{1}", "----", "----"));
            for (int i = 0; i < results.Count; i++) {
                string ip = results[i]["i"].ToString();
                string hostname = "";
                if (results[i].HasValue("name")) {
                    hostname = results[i].Value("name").ToString();
                }
                res.Add(String.Format("  {0,-20}{1}", ip, hostname));
            }
            Console.WriteLine(String.Join('\n', res));
        }

        [CmdCommand(Command = "import",
                    Description = "import nmap /path/to/nmap.xml   Import an Nmap XML file and add information\nimport recon-ng workspacename   Import hosts and ports from a Recon-NG workspace")]
        public void Import_XML(string arg) {
            var homedir = Environment.GetEnvironmentVariable("HOME");
	    if (arg.Length > 0) {
                string[] args = Regex.Split(arg, @"[\s+]");
		if (args[0] == "nmap") {
                    if (File.Exists(args[1])) {
                       string nmap_xml = File.ReadAllText(args[1]);
                       Parse_Nmap_XML(nmap_xml);
		       return;
                    } else {
                       this.nw.Error($"No such file: {args[1]}");
		    }
	        } else if (args[0] == "recon-ng") {
		    if (File.Exists($"{homedir}/.recon-ng/workspaces/{args[1]}/data.db")) {
			// https://docs.microsoft.com/en-us/dotnet/csharp/programming-guide/concepts/linq/creating-xml-trees-linq-to-xml-2
			// https://blog.tigrangasparian.com/2012/02/09/getting-started-with-sqlite-in-c-part-one/
	                SQLiteConnection conn;
		        conn = new SQLiteConnection($"Data Source={homedir}/.recon-ng/workspaces/{args[1]}/data.db;Version=3");
		        conn.Open();
		        string ipsql = "SELECT distinct(ip_address) FROM hosts WHERE ip_address IS NOT NULL";
		        SQLiteCommand cmd = new SQLiteCommand(ipsql, conn);
		        SQLiteDataReader ipreader = cmd.ExecuteReader();
			while (ipreader.Read()) {
			    XElement host = new XElement("nmaprun",
					     new XElement("host",
					      new XElement("address", new XAttribute("addr", ipreader["ip_address"]))
					      ),
					     new XElement("runstats",
				 	      new XElement("finished", new XAttribute("summary", "Added 1 host")))
					    );
			    this.Parse_Nmap_XML(host.ToString());
			}
		        string portsql = "SELECT distinct(ip_address), port FROM ports WHERE ip_address IS NOT NULL";
			SQLiteCommand portcmd = new SQLiteCommand(portsql, conn);
			SQLiteDataReader portreader = portcmd.ExecuteReader();
			while (portreader.Read()) {
			    XElement host = new XElement("nmaprun",
					     new XElement("host",
					      new XElement("address", new XAttribute("addr", portreader["ip_address"])),
					       new XElement("ports", 
						new XElement("port", new XAttribute("protocol", "tcp"), 
							             new XAttribute("portid", portreader["port"]),
						 new XElement("state", new XAttribute("state", "open"),
							               new XAttribute("reason", "syn-ack"))
					      ))),
					     new XElement("runstats",
				 	      new XElement("finished", new XAttribute("summary", "Added 1 host")))
					    );
			    this.Parse_Nmap_XML(host.ToString());
			}
		        conn.Close();
		        return;
		    } else {
			this.nw.Error($"No such recon-ng workspace: {args[1]}");
		    }
		}
	    } 
	    this.nw.Error("Usage: import nmap /path/to/nmap.xml  or import recon-ng workspacename");
        }

        [CmdCommand(Command = "ports",
                    Description = "Show known hosts, ports, and information")]
        public void Ports(string arg) {
            string filterexp = "";
            if (arg.Length > 0) {
                string[] p = Regex.Split(arg, @"[\s+]");
                string F = "";
                if (p[0] == "host") {
                    F = $@"?i = ""{p[1]}"" ";
                } else if (p[0] == "port") {
                    F = $@"?p = ""{p[1]}"" ";
                } else if (p[0] == "state") {
                    F = $@"?state = ""{p[1]}"" ";
                } else {
                    this.nw.Warn($"Unknown option: {p[0]}");
                    return;
                }
                filterexp = String.Format("FILTER ({0})", F);
            }

            SparqlQueryParser parser = new SparqlQueryParser();
            string query = @"PREFIX net: <http://example.com/schema/1/net#> 
    PREFIX vuln:  <http://example.com/schema/1/vuln#>
    PREFIX exploit:  <http://example.com/schema/1/exploit#>
    PREFIX cvss: <http://example.com/schema/1/cvss#>
    PREFIX rdf: <http://www.w3.org/1999/02/22-rdf-syntax-ns#> 
    
    SELECT DISTINCT 
        ?i ?p ?s ?proto ?state ?name ?cpe
    WHERE { ?x rdf:type net:IP  .
            ?x net:hasIp ?i .
            ?y rdf:type net:Port .
            ?x net:hasPort ?y .
            ?y net:hasNumber ?p .
            ?y net:hasProtocol ?proto .
        OPTIONAL { ?y net:hasServiceName ?s .
                   ?y net:hasState ?state } .
        OPTIONAL { ?x net:hasHostname ?hn .
                    ?hn net:hasDnsName ?name } .
        OPTIONAL { ?y net:hasCPE ?cpe }  
        FILTEREXP  
    }
    ORDER BY ?i ?p";
            query = query.Replace("FILTEREXP", filterexp);
            SparqlQuery q = parser.ParseFromString(query);            
            SparqlResultSet results = this.graph.ExecuteQuery(q) as SparqlResultSet;
            nw.Info($"Found {results.Count} Ports");
            var res = new List<string>();
            res.Add(String.Format("  {0,-20}{1,-48}{2,-8}{3,-7}{4,-12}{5,-14}{6}", "Host", "Name", "Proto", "Port", "State", "Service", "CPE"));
            res.Add(String.Format("  {0,-20}{1,-48}{2,-8}{3,-7}{4,-12}{5,-14}{6}", "----", "----", "-----", "----", "-----", "-------", "---"));
            for (int i = 0; i < results.Count; i++) {
                string ip = results[i]["i"].ToString();
                string hostname = "";
                if (results[i].HasValue("name")) {
                    hostname = results[i].Value("name").ToString();
                }
                string proto = results[i]["proto"].ToString();
                string port = results[i]["p"].ToString();
                string state = "";
                if (results[i].HasValue("state")) {
                    state = results[i]["state"].ToString();
                } 
                string service = "";
                if (results[i].HasValue("s")) {
                    service = results[i]["s"].ToString();
                } 
                string cpe = "";
                if (results[i].HasValue("cpe")) {
                    cpe = results[i]["cpe"].ToString();
                }
                res.Add(String.Format("  {0,-20}{1,-48}{2,-8}{3,-7}{4,-12}{5,-14}{6}", ip, hostname, proto, port, state, service, cpe));
            }
            Console.WriteLine(String.Join('\n', res));
        }

        [CmdCommand(Command = "rescan",
                    Description = "Rescans NSE directory")]
        public void Rescan(string unused) {
            // clear the modules 
            this.modules = new Dictionary<string, Nmap>();
            this.BuildModules();
        }

        [CmdCommand(Command = "restore",
                    Description = "Replays a session from a savefile")]
        public void Restore(string arg) {
            if (File.Exists(arg)) {
                string [] lines = File.ReadAllLines(arg);
                foreach (string line in lines) {
                    Console.WriteLine($"{CommandPrompt} {line}");
                    this.OneCmd(line);
                }
            } else {
                nw.Warn($"No such file {arg}");
            }
        }

        [CmdCommand(Command = "run",
                    Description = "Runs the selected module")]
        public void Run(string arg) {
            if (this.handler.categories.Length == 0) {
                nw.Warn("No selected module");
                return;
            }
            string res = this.handler.Run(this.global_options, this.Get_Hosts());
            if (res.Length > 0) {
                this.Parse_Nmap_XML(res);
            }
        }

        [CmdCommand(Command = "set",
                    Description = "Set a module specific option")]
        public void Set(string arg) {
            string[] args = Regex.Split(arg, @"[\s+]");
            if (args.Length < 2) {
                nw.Warn("Usage: set <option> <value>");
                return;
            }
            if (this.handler.Set_opt(args[0], String.Join(" ", args.Skip(1)))) {
                this.nw.Info(args[0] + " => " + String.Join(" ", args.Skip(1)));
            }
        }

        [CmdCommand(Command = "search",
                    Description = "Searches modules for the argument")]
        public void Search(string arg) {
            var results = new Dictionary<string, string>();
            foreach (KeyValuePair<string, Nmap> kv in this.modules) {
                if (kv.Key.Contains(arg)) {
                    results.Add(kv.Key, kv.Value.About());
                    continue;
                }
                if (kv.Value.About().Contains(arg)) {
                    if (!results.ContainsKey(kv.Key)) {
                        results.Add(kv.Key, kv.Value.About());
                    }
                }
            }
            if (results.Count == 0) {
                this.nw.Warn("No results found");
                return;
            }
            foreach (KeyValuePair<string, string> kv in results) {
                this.nw.Info($"{kv.Key}     {kv.Value}");
            }
        }

        [CmdCommand(Command = "setf",
                    Description = "Set a global flag")]
        public void Set_Flag(string arg) {
            string[] args = Regex.Split(arg, @"[\s+]");
            if (args.Length != 1) {
                nw.Warn("Usage: setf <flag>");
                return;
            }
            string flag = args[0];
            if (this.handler.Set_flag(flag)) {
                nw.Info($"flags += {flag}");
            } else {
                nw.Warn($"Flag {flag} already set");
            }
        }

        [CmdCommand(Command = "setg",
                    Description = "Set a global option")]
        public void Set_Global(string arg) {
            string[] args = Regex.Split(arg, @"[\s+]");
            if (args.Length != 2) {
                nw.Warn("Usage: setg <option> <value>");
                return;
            }
            string opt = args[0];
            string val = String.Join(" ", args.Skip(1));;
            if (this.global_options.ContainsKey(opt)) {
                var no = this.global_options[opt];
                this.global_options.Remove(opt);
                this.global_options.Add(opt, new NmapOption(val, no.odesc));
            } else {
                this.nw.Warn("No such option: " + opt);
            }
        }

        [CmdCommand(Command = "show",
                    Description = "Show information about modules or results: 'vulns', 'info', 'description', 'results'")]
        public void Show(string arg) {
            if (arg.StartsWith("vuln") || arg.StartsWith("expl")) {
                this.Show_Vulns();
                return;
            }
            if (this.handler.name.Length == 0) {
                this.nw.Warn("No module to show");
                return;
            }
            if (arg == "info") {
                Console.Write(this.handler.ToString() + "\r\n");
                return;
            }
            if (arg == "description") {
                Console.WriteLine(String.Join("\n", this.handler.GetWordGroups(this.handler.description, 100)));
                return;
            } 
	    if (arg == "options") {
		Console.WriteLine(String.Join("\r\n", this.handler.ListOptions()));
		return;
	    }
            if (arg == "results") {
                this.Show_Results(this.handler.name);
                return;
            }
        }

        [CmdCommand(Command = "sleep",
                    Description = "Sleep for N seconds")]
        public void Sleep(string arg) {
            int n = Int32.Parse(arg);
            Thread.Sleep(1000 * n);
        }

        [CmdCommand(Command = "unset", 
                    Description = "Unset the option")]
        public void Unset(string arg) {
            if (this.handler.Set_opt(arg, "")) {
                this.nw.Info($"{arg} => \"\"");
            }            
        }

        [CmdCommand(Command = "unsetf",
                    Description = "Unsets a flag")]
        public void Unset_Flag(string arg) {
            string[] args = Regex.Split(arg, @"[\s+]");
            if (args.Length != 1) {
                nw.Warn("Usage: unsetf <flag>");
                return;
            }
            string flag = args[0];
            if (this.handler.Unset_flag(flag)) {
                nw.Info($"flags -= {flag}");
            } else {
                nw.Warn($"Flag {flag} already unset");
            }
        }

        [CmdCommand(Command = "unsetg",
                    Description = "Unset a global option")]
        public void Unset_Global(string arg) {
            if (arg.Length < 1) {
                nw.Warn("Usage: unsetg <option>");
                return;
            }
            if (this.global_options.ContainsKey(arg)) {
                var no = this.global_options[arg];
                this.global_options.Remove(arg);
                this.global_options.Add(arg, new NmapOption("", no.odesc));
            } else {
                this.nw.Warn("No such option: " + arg);
            }
        }

        [CmdCommand(Command = "use",
                    Description = "Use the selected module")]
        public void Use(string arg) {
            Nmap nmap;
            nmap = new Nmap("");            
            if (this.modules.TryGetValue(arg, out nmap)) {
                this.handler = nmap;
                string name = $"\x1b[91m{this.handler.name}\x1b[0m";
                CommandPrompt = $"osail {this.handler.categories[0]}({name}) > ";
            } else {
                nw.Warn("NO SUCH MODULE");
            }
        }        

        [CmdCommand(Command = "workspace",
                    Description = "Show, change, or create a workspace")]
        public void Workspace(string arg) {
            var homedir = Environment.GetEnvironmentVariable("HOME");
            if (arg.Length == 0) {
                var workspaces = Directory.GetDirectories($"{homedir}/.osail/workspaces");
                Console.WriteLine(String.Format("{0,-4}{1,-20}{2,-24}{3,-24}", "", "Workspace", "Created", "Updated"));
                Console.WriteLine(String.Format("{0,-4}{1,-20}{2,-24}{3,-24}", "", "---------", "-------", "-------"));
                foreach (string workspacedir in workspaces) {
                    var workspace = new FileInfo(workspacedir).Name;
                    string pre = "   ";
                    if (workspace == this.workspace) {
                        pre = " * ";
                    }
                    string created = Directory.GetCreationTime(String.Format($"{workspaces}/{workspace}")).ToString();
                    string updated = Directory.GetCreationTime(String.Format($"{workspaces}/{workspace}/graph.rdf")).ToString();
                    Console.WriteLine(String.Format("{0,-4}{1,-20}{2,-24}{3,-24}", pre, workspace, created, updated));
                }
                return;
            }
            string[] cmds = arg.Split(" ");
            if (cmds[0] == "add") {
                this.Add_Workspace(cmds[1]);
                return;
            } else if (cmds[0] == "select") {
                this.Use_Workspace(cmds[1]);
                return;
            } else {
                this.nw.Warn($"Unknown option: {cmds[0]}");
                return;
            }
        }
    }

    class Program
    {
        
        static void ShowHelp (OptionSet p)
        {
            Console.WriteLine ("Options:");
            p.WriteOptionDescriptions (Console.Out);
        }

        static void Main(string[] args)
        {
            bool show_help = false;
            var homedir = Environment.GetEnvironmentVariable("HOME");
            if (!Directory.Exists(String.Format($"{homedir}/.osail"))) {
                Console.WriteLine($"directory {homedir}/.osail doesn't exist, creating");
                Directory.CreateDirectory($"{homedir}/.osail");
                Directory.CreateDirectory($"{homedir}/.osail/data");
		File.Copy("blank.rdf", $"{homedir}/.osail/data/blank_graph.rdf");
                Directory.CreateDirectory($"{homedir}/.osail/workspaces");
                Directory.CreateDirectory($"{homedir}/.osail/workspaces/default");
		File.Copy($"{homedir}/.osail/data/blank_graph.rdf", $"{homedir}/.osail/workspaces/default/graph.rdf");
            }
            string configfile = String.Format($"{homedir}/.osail/config.toml");
            if (!File.Exists(configfile)) {
                Console.WriteLine($"file {configfile} doesn't exist, copying from .");
                File.Copy("config.toml", configfile);
            }   
            string script = null;
            string workspace = "default";
            string nmap = "/usr/bin/nmap";
            string nsepath = "/usr/share/nmap/scripts";
            var nw = new NseWriter();
            nw.Info("Obsidian Sailboat is starting up ...");
            // http://tirania.org/blog/archive/2008/Oct-14.html
            var p = new OptionSet() {
                { "c|config", "configuration file (default: {configfile})",
                    v => configfile = v},
                { "h|help",  "show this message and exit", 
                    v => show_help = v != null },
                { "n|nmap=", $"path to nmap (default: {nmap})", 
                    v => nmap = v},
                { "N|nsepath=", $"path to NSE scripts (default: {nsepath})",
                    v => nsepath = v},
                { "s|script=", "the name of the script to replay at start",
                    v => script = v},
                { "w|workspace=", "the name of the workspace to use at start", 
                    v => workspace = v}
            };

            try {
                p.Parse (args);
            } 
            catch (OptionException e) { 
                Console.WriteLine($"Error: {e.Message}");
                return;
            }

            if (show_help) {
                ShowHelp (p);
                return;
            }

            var C = File.ReadAllText(configfile).ParseAsToml();;
            nmap = C.options.nmap;
	    if (!File.Exists(nmap)) {
		Console.WriteLine($"Fatal: Can't find {nmap}");
		return;
	    }
            nsepath = C.options.nsepath;
            workspace = C.options.workspace;

            var ServiceDetection = new Nmap(nmap);
            ServiceDetection.name = "tcp-service-discovery";
            ServiceDetection.path = nmap;
            ServiceDetection.description = "Probe open ports to determine service/version info";
            ServiceDetection.flags.Add("-sV");
            ServiceDetection.flags.Add("-A");
            ServiceDetection.args.Add("--version-intensity", new NmapOption("2", "Set from 0 (light) to 9 (try all probes)"));
            ServiceDetection.categories = new string[]{"default", "safe", "discovery", "version"};

            var TcpConnect = new Nmap(nmap);
            TcpConnect.name = "tcp-connect";
            TcpConnect.path = nmap;
            TcpConnect.description = "Probe open TCP ports with TCP connect(). Instead of writing raw packets as most other scan types do, Nmap asks the underlying operating system to establish a connection with the target machine and port by issuing the connect system call.";
            TcpConnect.flags.Add("-sT");
            TcpConnect.categories = new string[]{"default", "safe", "discovery"};

            var TcpSYN = new Nmap(nmap);
            TcpSYN.name = "tcp-syn";
            TcpSYN.path = nmap;
            TcpSYN.description = "Probe open TCP ports with SYN. It can be performed quickly, scanning thousands of ports per second on a fast network not hampered by restrictive firewalls. It is also relatively unobtrusive and stealthy since it never completes TCP connections.";
            TcpSYN.flags.Add("-sS");
            TcpSYN.categories = new string[]{"default", "safe", "discovery"};

            var UdpScan = new Nmap(nmap);
            UdpScan.name = "udp-scan";
            UdpScan.path = nmap;
            UdpScan.description = "Probe open UDP ports. UDP scan works by sending a UDP packet to every targeted port. For some common ports such as 53 and 161, a protocol-specific payload is sent to increase response rate, but for most ports the packet is empty unless the --data, --data-string, or --data-length options are specified.";
            UdpScan.flags.Add("-sU");
            UdpScan.categories = new string[]{"default", "safe", "discovery"};

            var DiscoveryScan = new Nmap(nmap);
            DiscoveryScan.name = "host-discovery";
            DiscoveryScan.path = nmap;
            DiscoveryScan.description = "Host discovery scan. The default host discovery done consists of an ICMP echo request, TCP SYN to port 443, TCP ACK to port 80, and an ICMP timestamp request by default.";
            DiscoveryScan.flags.Add("-sn");
            DiscoveryScan.categories = new string[]{"default", "safe", "discovery"};
            DiscoveryScan.args.Remove("RPORT");
            DiscoveryScan.args.Add("RPORT", new NmapOption("", "Not used for this scan type"));

            var SctpInit = new Nmap(nmap);
            SctpInit.name = "sctp-init";
            SctpInit.path = nmap;
            SctpInit.description = "SCTP INIT scan. It is mostly being used for SS7/SIGTRAN related services but has the potential to be used for other applications as well. SCTP INIT scan is the SCTP equivalent of a TCP SYN scan. ";
            SctpInit.flags.Add("-sY");
            SctpInit.categories = new string[]{"default", "safe", "discovery"};

            var SctpCookieEcho = new Nmap(nmap);
            SctpCookieEcho.name = "sctp-cookie-echo";
            SctpCookieEcho.path = nmap;
            SctpCookieEcho.description = "SCTP COOKIE ECHO scan. It takes advantage of the fact that SCTP implementations should silently drop packets containing COOKIE ECHO chunks on open ports, but send an ABORT if the port is closed.";
            SctpCookieEcho.flags.Add("-sZ");
            SctpCookieEcho.categories = new string[]{"default", "safe", "discovery"};

	    var Masscan = new Nmap(C.options.masscan);
	    Masscan.name = "masscan-discovery";
	    Masscan.path = C.options.masscan;
	    Masscan.description = "Host discovery using masscan, far more efficient for wide area service discovery than nmap.";
	    Masscan.flags.Remove("-R");
	    Masscan.nmap_args.Remove("--dns-servers");
	    Masscan.nmap_args.Remove("--min-parallelism");
	    Masscan.nmap_args.Remove("--max-parallelism");
	    Masscan.nmap_args.Remove("--max-retries");
	    Masscan.nmap_args.Remove("--max-scan-delay");
	    Masscan.nmap_args.Remove("--host-timeout");
	    Masscan.categories = new string[]{"default", "discovery"};

            var nseshell = new NseShell(nmap, nsepath, workspace);
            nseshell.modules.Add("discovery/tcp/connect", TcpConnect);
            nseshell.modules.Add("discovery/tcp/syn", TcpSYN);
            nseshell.modules.Add("discovery/tcp/service-discovery", ServiceDetection);
            nseshell.modules.Add("discovery/sctp/sctp-init", SctpInit);
            nseshell.modules.Add("discovery/sctp/sctp-cookie-echo", SctpCookieEcho);
            nseshell.modules.Add("discovery/udp/scan", UdpScan);
            nseshell.modules.Add("discovery/ping/host-discovery", DiscoveryScan);
	    nseshell.modules.Add("discovery/tcp/masscan-discovery", Masscan);

            //TcpConnect.Set_opt("RHOST", "195.22.127.231");
            //TcpConnect.Run(nseshell.global_options, new List<string>());
	    //var Censys = new Nmap(nmap, "/usr/share/nmap/scripts/censys-api.nse");
            //Censys.Run(nseshell.global_options, nseshell.Get_Hosts());
            nseshell.OneCmd("banner");
            nw.Info("Welcome to Obsidian Sailboat");
            nseshell.HistoryFileName = String.Format($"{homedir}/.osail/commands");
            nw.Info("Loaded " + nseshell.modules.Keys.Count + " modules");
            if (workspace != "default") {
                nseshell.OneCmd($"workspace select {workspace}");
            }
            if (script != null) {
                nseshell.OneCmd($"restore {script}");
            }
            nseshell.CmdLoop();
            nw.Info("All done.");
        }
    }
}
