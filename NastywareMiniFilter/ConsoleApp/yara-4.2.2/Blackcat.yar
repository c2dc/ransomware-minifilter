import "pe"

rule blackcat_cluster
{


	condition:
		pe.imports("advapi32.dll", "RegSetValueExW") and 
		pe.imports("kernel32.dll", "CreateThread") and 
		pe.imports("kernel32.dll", "ReadFile") and 
		pe.imports("kernel32.dll", "FindNextFileW") and 
		pe.imports("kernel32.dll", "GetTickCount") and 
		pe.imports("kernel32.dll", "ExitProcess") and 
		pe.imports("kernel32.dll", "TerminateProcess") and 
		pe.imports("kernel32.dll", "CreateFileW") and 
		pe.imports("kernel32.dll", "OpenProcess") and 
		pe.imports("kernel32.dll", "GetCurrentProcessId") and 
		pe.imports("kernel32.dll", "GetTempPathW") and 
		pe.imports("kernel32.dll", "CloseHandle")

}
