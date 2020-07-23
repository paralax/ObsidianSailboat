using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Text.RegularExpressions;

namespace ObsidianSailboat
{
    class NmapOption 
    {
        public string oval;
        public string odesc;
        public NmapOption(string oval, string odesc) {
            this.oval = oval;
            this.odesc = odesc;
        }
    }

    class Nmap
    {
        public string nmap_path;
        public string license;
        public Dictionary<string, NmapOption> args;
        public Dictionary<string, NmapOption> nmap_args;
        public HashSet<string> flags;
        public string author;
        public string name;
        public string path;
        public string description;
        public string[] script;
        public string[] categories;
        public Nmap(string nmap_path) {
            // Using Nmap's built in functionality
	    this.Init();
            this.nmap_path = nmap_path;
            this.path = nmap_path;
            this.name = "";
            this.author = "Fyodor";
            this.categories = new string[] {};
            this.description = "";
            this.license = "Nmap--See https://nmap.org/book/man-legal.html";
            this.args.Add("RPORT", new NmapOption("80", "The target port"));
        }

        public Nmap(string nmap_path, string nse_path) {
            // Using NSE scripts
	    this.Init();
            this.nmap_path = nmap_path;
            this.path = nse_path;
            this.name = System.IO.Path.GetFileName(this.path).Replace(".nse", "");
            this.script = System.IO.File.ReadAllLines(nse_path);
            string portspec = this.Parse_Portspec();
            this.args.Add("RPORT", new NmapOption(portspec, "The target port"));
            this.author = this.Parse_Author();
            this.categories = this.Parse_Categories();
            this.description = this.Parse_Description();
            this.license = this.Parse_License();
            this.Parse_Args();
        }
		
	private void Init() {
            this.args = new Dictionary<string, NmapOption>();
            this.nmap_args = new Dictionary<string, NmapOption>();
            this.script = new string[] {};
            this.args.Add("RHOST", new NmapOption("default", "The target address"));
            this.nmap_args.Add("http.useragent", new NmapOption("", "User-agent to set for HTTP requests"));
	    this.nmap_args.Add("--dns-servers", new NmapOption("8.8.8.8", "Specify custom DNS servers"));
	    this.nmap_args.Add("--min-parallelism", new NmapOption("8", "Probe parallelization minimum"));
	    this.nmap_args.Add("--max-parallelism", new NmapOption("256", "Probe parallelization maximum"));
	    this.nmap_args.Add("--max-retries", new NmapOption("3", "Caps number of port scan probe retransmissions"));
	    this.nmap_args.Add("--max-scan-delay", new NmapOption("0", "Adjust delay between probes"));
	    this.nmap_args.Add("--host-timeout", new NmapOption("10s", "Give up on target after this long"));
	    this.nmap_args.Add("--min-rate", new NmapOption("10000", "Send packets at least <number> per second"));
	    this.nmap_args.Add("--max-rate", new NmapOption("65535", "Send packets no faster than <number> per second"));
            this.flags = new HashSet<string>();
	    this.flags.Add("-sV");
	    this.flags.Add("-R");
	    this.flags.Add("-oX -");			
	}

        public string About() {
            string[] res = Regex.Split(this.description, @"\.\s+");
            if (res.Length > 0) {
                return res[0];
            } else {
                return "";
            }
        }

        public List<string> Name_Branch() {
            string[] ab = this.name.Split("-");
            string[] protos = "dns,ssh,vnc,ipv6,telnet,irc,modbus,tls,ssl,smb,smb2,targets,whois,pop3,socks,mysql,citrix".Split(',');
            List<string> names = new List<string>();
            string cmdname;
            if (ab.Length > 1) {
                if (ab[0].EndsWith('p') || Array.IndexOf(protos, ab[0]) > -1) {
                    foreach (string cat in this.categories) {
                        cmdname = String.Join("/", new string[]{cat, ab[0], this.name});
                        names.Add(cmdname);
                    }
                } else {
		    foreach (string cat in this.categories) {
		       cmdname = String.Join("/", new string[]{cat, this.name});
		       names.Add(cmdname);
		    }
		}
            } else {
                foreach (string cat in this.categories) {
                    cmdname = String.Join("/", new string[]{cat, this.name});
                    names.Add(cmdname);
                }
            }
            return names;
        }

        public void Parse_Args() {
            string pattern = @"--\s+@args\s+";
            foreach (string line in this.script) {
                Match m = Regex.Match(line, pattern);
                if (m.Success) {
                    string[] info = line.Split(new char[]{' ', '\t'}, 4);
                    string desc = "";
                    if (info.Length > 3) {
                        desc = info[3];                        
                    }
                    this.args.Add(info[2], new NmapOption("", desc));
                }
            }
        }

        public string Parse_Author() {
            string pattern = @"author\s+=\s+(.+)";
            Match m = Regex.Match(String.Join("\n", this.script), pattern);
            if (m.Success) {
                string author = Regex.Replace(m.Value, @"author\s+=\s+", "");
                return author.Replace("}", "").Replace("{", "").Replace("\"", "");
            }
            return "";
        }

        public string[] Parse_Categories() {
            string pattern = @"categories\s+=\s{([^}]+)}";
            Match m = Regex.Match(String.Join(" ", this.script), pattern);
            if (m.Success) {
                return m.Value.Replace(" ", "").Replace("\"", "").Replace("'", "").Replace("}", "").Replace("{", "").Replace("categories=", "").Split(",");
            }
            return new string[]{};
        }

        public string Parse_Description() {
            string pattern = @"description = \[\[([^]])+\]\]";
            Match m = Regex.Match(String.Join(" ", this.script), pattern, RegexOptions.Singleline);
            if (m.Success) {
                return Regex.Replace(m.Value, @"description\s+=\s+\[\[\s+", "").TrimEnd(']');
            }
            return "";
        }

        public string Parse_License() {
            string pattern = @"license\s+=\s+(.+)";
            Match m = Regex.Match(String.Join("\n", this.script), pattern);
            if (m.Success) {
                string license = Regex.Replace(m.Value, @"license\s+=\s+", "");
                return license.Replace("}", "").Replace("{", "").Replace("\"", "");
            }
            return "";
        }

        public string Parse_Portspec() {
            // handle     portrule = shortport.port_or_service( {5900, 5901, 5902} , "vnc", "tcp", "open")
            string pat = @"(\d+)";
            var res = new List<string>();
            foreach (string line in this.script) {
		if (line.Contains("udp")) {
		    this.flags.Add("-sU");
		}
                if (line.Contains("portrule = irc.portrule") || Regex.Match(line, "portrule = irc.portrule").Success) {
                    return "6667";
                }
                if (line.Contains("smb.get_port") || Regex.Match(line, "smb.get_port").Success) {
                    return "139,445";
                }
                if (line.Contains("shortport.http") || Regex.Match(line, "shortport.http").Success) {
                    return "80,443,631,7080,8080,8443,8088,5800,3872,8180,8000";
                }
                if (line.Contains("shortport.ssl") || Regex.Match(line, "shortport.ssl").Success) {
                    return "261,271,563,6679,5061,6697,2221,4911,8883,443,3389,324,3269,2376,585,2252,5986,465,853,989,990,992,993,994,995,9001,8443,636";
                }
                if (line.Contains("shortport.port") || Regex.Match(line, "shortport.port").Success) {
                    MatchCollection ms = Regex.Matches(line, pat);
                    for (int i = 0; i < ms.Count; i++) {
                        res.Add(ms[i].Value);
                    }
                    if (res.Count > 0) {
                        return String.Join(",", res);
                    }
                }
            }
            return "80";
        }

        public string Run(Dictionary<string, NmapOption> global_flags, List<string> hosts) {
            string flags = String.Join(" ", this.flags);
            string script = "";
            string script_args = "";
            string extra_args = "";
            if (this.script.Length > 0) {
                script = "--script " + this.name;
                script_args = "--script-args \"";
                foreach (KeyValuePair<string, NmapOption> kv in this.args) {
                    if (kv.Key == "RHOST" || kv.Key == "RPORT") {
                        continue;
                    }
                    if (kv.Value.oval.Trim().Length == 0) {
                        continue;
                    }
                    script_args = $"{script_args},{kv.Key}={kv.Value.oval}".TrimStart(',');
                }
                script_args = script_args + "\"";
                if (script_args.Length < 20) {
                    script_args = "";
                }
            } else {
                // e.g. built in nmap commands
                foreach (KeyValuePair<string, NmapOption> kv in this.args) {
                    if (kv.Key == "RHOST" || kv.Key == "RPORT") {
                        continue;
                    }
                    if (kv.Value.oval.Trim().Length == 0) {
                        continue;
                    }
                    extra_args = $"{extra_args} {kv.Key} {kv.Value.oval}";
                }
            }
            string g_flags = "";
            foreach (KeyValuePair<string, NmapOption> kv in global_flags) {
                if (kv.Value.oval.Length > 0) {
                    g_flags = g_flags + " " + kv.Key + " " + kv.Value.oval;
                }
            }
	    string n_args = "";
	    foreach (KeyValuePair<string, NmapOption> kv in this.nmap_args) {
		if (kv.Value.oval.Length > 0) {
		    n_args = n_args + " " + kv.Key + " " + kv.Value.oval;
		}
	    }
	    string ports;
            try {
		ports = this.args["RPORT"].oval;
	    } 
	    catch {
		ports = "";
	    }
            if (ports.Length > 0) {
                ports = "-p " + ports;
            }
            string hostspec = this.args["RHOST"].oval;
            if (hostspec == "default" || hostspec.Trim().Length == 0) {
                hostspec = String.Join(' ', hosts);
            }
            string cmd = $" {ports} {extra_args} {flags} {n_args} {g_flags} {script} {script_args} {hostspec}";
            Console.WriteLine(this.nmap_path + " " + cmd);

            Process process = new Process {
                StartInfo = new ProcessStartInfo {
                    FileName = this.nmap_path,
                    Arguments = cmd,
                    UseShellExecute = false,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    CreateNoWindow = true
                }
            };
            
            process.Start();
            string output = process.StandardOutput.ReadToEnd();
            string error = process.StandardError.ReadToEnd();            
            process.WaitForExit();
            process.Close();
            if (error.Length > 0) {
                var nw = new NseWriter();
                nw.Error($"Error seen: {error}");
            }
            return output;
        }

        public bool Set_flag(string flag) {
            return this.flags.Add(flag);
        }

        public bool Set_opt(string opt, string val) {
            if (this.args.ContainsKey(opt)) {
                var no = this.args[opt];
                this.args.Remove(opt);
                this.args.Add(opt, new NmapOption(val, no.odesc));
                return true;
	    } 
	    if (this.nmap_args.ContainsKey(opt)) {
		var no = this.nmap_args[opt];
		this.nmap_args.Remove(opt);
		this.nmap_args.Add(opt, new NmapOption(val, no.odesc));
		return true;
	    }
            var nw = new NseWriter();
            nw.Warn("No such option: " + opt);
            return false;
        }

        public bool Unset_flag(string flag) {
            return this.flags.Remove(flag);
        }

        // https://stackoverflow.com/a/41330876
        public List<string> GetWordGroups(string text, int limit) {
            var words = text.Split(new string[] { " ", "\r\n", "\n" }, StringSplitOptions.None);

            List<string> wordList = new List<string>();

            string line = "";
            foreach (string word in words)
            {
                if (!string.IsNullOrWhiteSpace(word))
                {
                    var newLine = string.Join(" ", line, word).Trim();
                    if (newLine.Length >= limit)
                    {
                        wordList.Add(line);
                        line = word;
                    }
                    else
                    {
                        line = "  " + newLine;
                    }
                }
            }

            if (line.Length > 0)
                wordList.Add(line);

            return wordList;
        }

        public List<string> ListOptions() {
            var res = new List<string>();
            res.Add("\r\n");
            res.Add("Options:");
            res.Add(String.Format("  {0,-40} {1,-20} {2}", "Name", "Current Setting", "Description"));
            res.Add(String.Format("  {0,-40} {1,-20} {2}", "----", "---------------", "-----------"));
            string row;
            foreach (KeyValuePair<string, NmapOption> kv in this.args) {                
                row = String.Format("  {0,-40} {1,-20} {2}", kv.Key, kv.Value.oval, kv.Value.odesc);
                res.Add(row);
            }
            return res;
        }

        public List<string> ListNmapArgs() {
            var res = new List<string>();
            res.Add("\r\n");
            res.Add("Nmap Arguments:");
            res.Add(String.Format("  {0,-40} {1,-20} {2}", "Name", "Current Setting", "Description"));
            res.Add(String.Format("  {0,-40} {1,-20} {2}", "----", "---------------", "-----------"));
            string row;
            foreach (KeyValuePair<string, NmapOption> kv in this.nmap_args) {                
                row = String.Format("  {0,-40} {1,-20} {2}", kv.Key, kv.Value.oval, kv.Value.odesc);
                res.Add(row);
            }
            return res;
        }

        public override string ToString() {
            string name = String.Format("{0,18} {1}", "Name: ", this.name);
            string module = String.Format("{0,18 }{1}", "Module: ", this.path);
            string author = String.Format("{0,18 }{1}", "Author(s): ", String.Join(", ", this.author));
            string license = String.Format("{0,18 }{1}", "License: ", this.license);
            string categories = String.Format("{0,18 }{1}", "Categories: ", String.Join(", ", this.categories));
            string[] res = {name, module, author, license, categories};
            string desc = String.Join("\n", this.GetWordGroups(this.description, 100));
            return ($"{String.Join("\r\n", res)}{String.Join("\r\n", this.ListNmapArgs())}{String.Join("\r\n", this.ListOptions())}\r\nDescription:\r\n{desc}");
        }  
    }
}
