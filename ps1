#requires -version 3
#-----------------------------------------------------------------------------#
#                                                                             #
#   Function        Invoke-SolarwindsCommand                                  #
#                                                                             #
#   Description     Funcao para executar comando remotamente atravs do        #
#					Invoke-PsExec, essa funcao sera chamada via Alerts 		              #
#					do Solarwinds.						                                          #
#                                                                             #
#   Notes:          Versao 1.0 												                        #
#                   Criado por: Gregorio Oliveira							                #
#                   						                                              #
#                                                                             #
#   History                                                                   #
#    2019-10-01 Gregorio Oliveira Criacao.				                            #
#    2019-12-17 Gregorio Oliveira Inclusao de Query para Update da tabela     #
#				do Service Now no Solarinwds                                          #
#-----------------------------------------------------------------------------#

<#
   .SYNOPSIS
       Função para encerrar chamados no service now via API

   .PARAMETER IncidentNumber
		IP address ou nome do computador.
#>
[CmdletBinding()]
param(
	[Parameter(Mandatory=$True,ValueFromPipeline=$True,ValueFromPipelineByPropertyName=$True)][ValidateNotNullOrEmpty()][string]$IncidentNumber
)
$datelog = Get-Date -format "yyyy_MM_dd" #Mapear a data do log
$logDir = "E:\ScriptAction\ClosecasesSN\Logs" #Pasta para arquivo de Log
$logFile = "$logDir\$datelog"+"_execution.log" #arquivo de Log
$logName = "Application"

Function Now {
	Param (
		[Switch]$ms,        # Append milliseconds
		[Switch]$ns         # Append nanoseconds
	)
	$Date = Get-Date
	$now = ""
	$now += "{0:0000}-{1:00}-{2:00} " -f $Date.Year, $Date.Month, $Date.Day
	$now += "{0:00}:{1:00}:{2:00}" -f $Date.Hour, $Date.Minute, $Date.Second
	$nsSuffix = ""
	if ($ns) {
		if ("$($Date.TimeOfDay)" -match "\.\d\d\d\d\d\d") {
		$now += $matches[0]
		$ms = $false
		} else {
		$ms = $true
		$nsSuffix = "000"
		}
	} 
	if ($ms) {
		$now += ".{0:000}$nsSuffix" -f $Date.MilliSecond
	}
	return $now
}

Function Log {
	Param(
		[Parameter(Mandatory=$false, ValueFromPipeline=$true, Position=0)]
		[String]$string
	)
	if (!(Test-Path $logDir)) {
		New-Item -ItemType directory -Path $logDir | Out-Null
	}
	if ($String.length) {
		$string = "$(Now) $pid $currentUserName $string"
	}
	$string | Out-File -Encoding UTF8 -Append "$logFile"
}

Function ExecutionQuery{
	Param(
		$Query
	)
	Invoke-Sqlcmd -Query $Query -HostName <servername> -ServerInstance "<instancename>" -Database SolarWindsOrion -userName "<dbusername>" -Password "<password>" -ErrorAction Stop
	return
}

Function CheckServiceNow{
	Param(
		$funcao,
		$body,
		$url
	)
	#condicional para criação de tunel ssl
	if (-not ([System.Management.Automation.PSTypeName]'ServerCertificateValidationCallback').Type){
		$certCallback = @"
			using System;
			using System.Net;
			using System.Net.Security;
			using System.Security.Cryptography.X509Certificates;
			public class ServerCertificateValidationCallback
			{
				public static void Ignore()
				{
					if(ServicePointManager.ServerCertificateValidationCallback ==null)
					{
						ServicePointManager.ServerCertificateValidationCallback += 
							delegate
							(
								Object obj, 
								X509Certificate certificate, 
								X509Chain chain, 
								SslPolicyErrors errors
							)
							{
								return true;
							};
					}
				}
			}
"@
		Add-Type $certCallback
	}#close if
	[ServerCertificateValidationCallback]::Ignore()	

	# Eg. User name="admin", Password="admin" for this code sample.
	$user = "user"
	$pass = "password"
	
	# Build auth header
	$base64AuthInfo = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes(("{0}:{1}" -f $user, $pass)))
	
	# Set proper headers
	$headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
	$headers.Add('Authorization',('Basic {0}' -f $base64AuthInfo))
	$headers.Add('Accept','application/json')
	$headers.Add('Content-Type','application/json')
    $proxy = "http://proxyaddress:port"
	
	#update incident
	if($funcao -eq 'GET'){
		Try{
			# Send HTTP request
			[Net.ServicePointManager]::SecurityProtocol = "tls12, tls11, tls"
			$returnSN = Invoke-RestMethod -Headers $headers -Proxy $proxy -uri $url -Method GET -ErrorAction Stop
			return $returnSN
		}
		catch{
			Log "$_.Exception.Message"
            exit
		}
	}
	else{
		Try{
			# Send HTTP request
			[Net.ServicePointManager]::SecurityProtocol = "tls12, tls11, tls"
			$returnSN = Invoke-RestMethod -Headers $headers -Proxy $proxy -Method put -Uri $url -Body $body -ErrorAction Stop
			return $returnSN	
		}
		catch{
			Log "$_.Exception.Message"
            exit
		}
	}
}

Log "Start Action: Recuperando SysID do Incidente: $IncidentNumber"
$Query = "SELECT IncidentID FROM [dbo].[SNI_AlertIncidents] WHERE IncidentNumber = "+"'"+$IncidentNumber+"'"

$SysID = (ExecutionQuery -Query $Query) | Select -ExpandProperty IncidentID
Log "SysID identificado: $SysID"
Log "Verificando status do Inciente"
# Specify endpoint uri
$url = "https://instancename.service-now.com/api/now/table/incident/$SysID"
$responsestate = CheckServiceNow -funcao 'GET' -url $url
if($responsestate.result.incident_state -ne 7){
	# criação do json de payload
	$body = @"
	{"work_notes":"Chamado encerrado via action","close_notes":"Alert reset - issue detected as resolved by Orion.","close_code":"Automatically resolved by monitoring","incident_state":"7"}
"@

	$response = CheckServiceNow -funcao 'POST' -url $url -body $body
	if($response.result.incident_state -eq 7){
		$QueryUP = "UPDATE SNI_AlertIncidents SET AlertTriggerState = 0, LogicalState = 3, State = 'Closed' where IncidentNumber = '"+$IncidentNumber+"'"
		Log "Resultado: Incidente: $IncidentNumber fechado via action e base de dados atualizada"
        exit
    }
}
else{
	$url = $responsestate.result.closed_by.link
	$responseuser = CheckServiceNow -funcao 'GET' -url $url
	if($responseuser.result.name -eq 'Cco Solar'){
		Log "Resultado: Incidente: $IncidentNumber fechado via instegração nativa"
		exit
	}
	else{
		Log "Resultado: Incidente: $IncidentNumber encerrado pelo usuário $responseuser.result.name"
		exit
	}
}
exit
