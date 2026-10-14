rule EICAR_Test_File
{
    meta:
        description = "EICAR antivirus test file"
        severity = "critical"
    strings:
        $marker = "EICAR-STANDARD-ANTIVIRUS-TEST-FILE!"
    condition:
        $marker
}

rule Autorun_Open_Executable
{
    meta:
        description = "autorun.inf that launches a program"
        severity = "high"
    strings:
        $section = "[autorun]" nocase
        $launch = /(open|shellexecute|shell\\open\\command)\s*=\s*\S+\.(exe|bat|cmd|scr|vbs|lnk)/ nocase
    condition:
        $section and $launch
}

rule PowerShell_Download_And_Execute
{
    meta:
        description = "PowerShell download cradle combined with execution"
        severity = "high"
    strings:
        $download = /(downloadstring|downloadfile|invoke-webrequest|net\.webclient)/ nocase
        $execute = /(invoke-expression|\biex\b|start-process)/ nocase
    condition:
        $download and $execute
}

rule Embedded_PE_In_Script
{
    meta:
        description = "Script containing an embedded base64 PE header"
        severity = "high"
    strings:
        $pe_base64 = "TVqQAAMAAAAEAAAA"
        $decode = /(frombase64string|base64\s+-d|certutil\s+-decode)/ nocase
    condition:
        $pe_base64 and $decode
}
