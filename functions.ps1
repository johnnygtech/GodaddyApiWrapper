<#
#GET /v1/domains Retrieve a list of Domains for the specified Shopper
PATCH /v1/domains/{domain} Update details for the specified Domain
#GET /v1/domains/{domain} Retrieve details for the specified Domain
DELETE /v1/domains/{domain} Cancel a purchased domain
PATCH /v1/domains/{domain}/contacts Update domain
DELETE /v1/domains/{domain}/privacy Submit a privacy cancellation request for the given domain
POST /v1/domains/{domain}/privacy/purchase Purchase privacy for a specified domain
PATCH /v1/domains/{domain}/records Add the specified DNS Records to the specified Domain
PUT /v1/domains/{domain}/records Replace all DNS Records for the specified Domain
#GET /v1/domains/{domain}/records/{type?}/{name?} Retrieve DNS Records for the specified Domain, optionally with the specified Type and/or Name
PUT /v1/domains/{domain}/records/{type} Replace all DNS Records for the specified Domain with the specified Type
PUT /v1/domains/{domain}/records/{type}/{name} Replace all DNS Records for the specified Domain with the specified Type and Name
POST /v1/domains/{domain}/renew Renew the specified Domain
POST /v1/domains/{domain}/transfer Purchase and start or restart transfer process
POST /v1/domains/{domain}/verifyRegistrantEmail Re-send Contact E-mail Verification for specified Domain
#GET /v1/domains/agreements Retrieve the legal agreement(s) required to purchase the specified TLD and add-ons
POST /v1/domains/available Determine whether or not the specified domains are available for purchase
#GET /v1/domains/available Determine whether or not the specified domain is available for purchase
POST /v1/domains/contacts/validate Validate the request body using the Domain Contact Validation Schema for specified domains.
#GET /v1/domains/identityDocuments Get a collection of identity documents the current shopper owns
POST /v1/domains/identityDocuments Create an Identity Document from uploaded image
POST /v1/domains/identityDocuments/{identityDocumentId}/verifications Initiate verifications for the specified Domains
#GET /v1/domains/identityDocuments/{identityDocumentId}/verifications Retrieve a list of Verifications for the specified Identity Document
POST /v1/domains/purchase Purchase and register the specified Domain
#GET /v1/domains/purchase/schema/{tld} Retrieve the schema to be submitted when registering a Domain for the specified TLD
POST /v1/domains/purchase/validate Validate the request body using the Domain Purchase Schema for the specified TLD
GET /v1/domains/suggest Suggest alternate Domain names based on a seed Domain, a set of keywords, or the shopper's purchase history
GET /v1/domains/tlds Retrieves a list of TLDs supported and enabled for sale
#>
$apiVersion = "v1"
$global:GD_API_ROOT = "https://api.godaddy.com/$apiVersion/domains"
$global:GD_API_CRED # = $(Get-Credential)

function Set-GDAuthorizationHeader
{
    <#
    .SYNOPSIS Prompts for username and password which are the apikey and secret for your go daddy account
    .DESCRIPTION Prompts for username and password which are the apikey and secret for your go daddy account
    #>
    $global:GD_API_CRED = $(Get-Credential)     
}

function Get-GDAuthorizationHeader
{
    <#
    .SYNOPSIS Return the correctly formatted authorization header with apikey and secret for your go daddy account
    .DESCRIPTION Return the correctly formatted authorization header with apikey and secret for your go daddy account.  Prompts if none set.
    #>
    if(!$global:GD_API_CRED)
    {
        Set-GDAuthorizationHeader
    }

    $netCred = $global:GD_API_CRED.GetNetWorkCredential()
    return @{"Authorization"="sso-key $($netCred.Username):$($netCred.Password)"}
}

function Get-GDDomains
{
    <#
    .SYNOPSIS Retrieve a list of Domains for the specified Shopper
    .DESCRIPTION Retrieve a list of Domains for the specified Shopper
    #>

    $relative_Url = ""
    $header = Get-GDAuthorizationHeader
    Write-Debug "$global:GD_API_ROOT$relative_Url"
    Write-Debug $($header)
    Invoke-RestMethod -uri "$($global:GD_API_ROOT)$relative_Url" -headers $header
}

function Get-GDDomain
{
    <#
    .SYNOPSIS Retrieve details for the specified Domain
    .DESCRIPTION Retrieve details for the specified Domain
    #>
    param(
        [parameter(Mandatory=$true)]$domain
    );
    switch($domain.GetType().Name)
    {
        "string"
        {
            $relative_Url = "/$domain"
        }
        "Object[]"
        {
            Foreach($domain in $domains)
            {
                $relative_Url = "/$($domain.Domain)"
            }
        }
        default 
        {
            Write-Error ""
        }
    }
    $header = Get-GDAuthorizationHeader
    Write-Debug "$global:GD_API_ROOT$relative_Url"
    Write-Debug $($header)
    Invoke-RestMethod -uri "$($global:GD_API_ROOT)$relative_Url" -headers $header   
}

function Get-GDDomainDNS
{
    <#
    .SYNOPSIS Retrieve DNS Records for the specified Domain, optionally with the specified Type and/or Name
    .DESCRIPTION Retrieve DNS Records for the specified Domain, optionally with the specified Type and/or Name
    .PARAMETER Type
        String filters the results of the query to only items matching this type
    .PARAMETER Name
        String filters the results of the query to only items matching this name
    #>
    param(
        [parameter(Mandatory=$true)]$domain,
        [parameter()]$type,
        [parameter()]$name
    );

    switch($domain.GetType().Name)
    {
        "string"
        {
            $relative_Url = "/$domain/records"
            if($type)
            {
                $relative_Url += "/$type"
                if($name)
                {
                    $relative_Url += "/$name"
                }
            }
        }
        "PSCustomObject"
        {
            $relative_Url = "/$($domain.Domain)/records"
            if($type)
            {
                $relative_Url += "/$type"
                if($name)
                {
                    $relative_Url += "/$name"
                }
            }
        }
        "Object[]"
        {
            Write-Error "Multiple Domain objects not supported"
        }
        default 
        {
            Write-Error ""
        }
    }
    $header = Get-GDAuthorizationHeader
    Write-Debug "$global:GD_API_ROOT$relative_Url"
    Write-Debug $($header)
    Invoke-RestMethod -uri "$($global:GD_API_ROOT)$relative_Url" -headers $header
}


function Get-GDDomainAgreement
{
    <#
    .SYNOPSIS Retrieve the legal agreement(s) required to purchase the specified TLD and add-ons
    .DESCRIPTION Retrieve the legal agreement(s) required to purchase the specified TLD and add-ons
    .PARAMETER
    #>
    param(
        [parameter(Mandatory=$true)]$domains,
        [parameter()]$XMarketId,
        [parameter()][switch]$privacy,
        [parameter()][switch]$forTransfer
    );
    ##TODO: Handle object switch of domains
    $relative_Url = "/agreements?tlds=$($domains -join ",")$(if($privacy){'&privacy=True'}else{'&privacy=False'})$(if($forTransfer){'&forTransfer=True'}else{'&forTransfer=False'})"
    $header = Get-GDAuthorizationHeader
    if($XMarketId)
    {
        $header.Add("X-Market-ID",$XMarketId)
    }
    Write-Debug "$global:GD_API_ROOT$relative_Url"
    Write-Debug $($header)
    $(Invoke-RestMethod -uri "$($global:GD_API_ROOT)$relative_Url" -headers $header).Content
}

function Test-GDDomainAvailability
{
    <#
    .SYNOPSIS Determine whether or not the specified domain is available for purchase
    .DESCRIPTION Determine whether or not the specified domain is available for purchase
    .PARAMETER
    #>
    param(
        [parameter(Mandatory=$true)]$domain,
        [parameter()][validateSet("FAST","FULL")]$checkType = "FAST",
        [parameter()][switch]$forTransfer
    );
    ##TODO: Handle object switch of domains
    $relative_Url = "/available?domain=$domain$(if($checkType -eq 'FAST'){'&checkType=FAST'}else{'&checkType=FULL'})$(if($forTransfer){'&forTransfer=True'}else{'&forTransfer=False'})"
    $header = Get-GDAuthorizationHeader
    Write-Debug "$global:GD_API_ROOT$relative_Url"
    Write-Debug $($header)
    Invoke-RestMethod -uri "$($global:GD_API_ROOT)$relative_Url" -headers $header
}

function Get-GDDomainIdentityDocuments
{
    <#
    .SYNOPSIS Determine whether or not the specified domain is available for purchase
    .DESCRIPTION Determine whether or not the specified domain is available for purchase
    .PARAMETER
    #>
    param(
        [parameter()]$XShopperId
    );
    ##TODO: Handle object switch of domains
    $relative_Url = "/identityDocuments"
    $header = Get-GDAuthorizationHeader
    if($XShopperId)
    {
        $header.Add("X-Shopper-Id",$XShopperId)
    }
    Write-Debug "$global:GD_API_ROOT$relative_Url"
    Write-Debug $($header)
    Invoke-RestMethod -uri "$($global:GD_API_ROOT)$relative_Url" -headers $header
}

function Get-GDDomainIdentityDocumentVerifications
{
   <#
    .SYNOPSIS Retrieve a list of Verifications for the specified Identity Document
    .DESCRIPTION Retrieve a list of Verifications for the specified Identity Document
    .PARAMETER
    #>
    param(
        [parameter(mandatory=$true)]$documentId,
        [parameter()]$domain,
        [parameter()]$XShopperId
    );
    ##TODO: Handle object switch of domains
    $relative_Url = "/identityDocuments/$documentID/verifications$(if($domain){'?tlds='+$domain}else{})"
    $header = Get-GDAuthorizationHeader
    if($XShopperId)
    {
        $header.Add("X-Shopper-Id",$XShopperId)
    }
    Write-Debug "$global:GD_API_ROOT$relative_Url"
    Write-Debug $($header)
    Invoke-RestMethod -uri "$($global:GD_API_ROOT)$relative_Url" -headers $header
}

function Get-GDDomainPurchaseSchema
{
    <#
    .SYNOPSIS Retrieve the schema to be submitted when registering a Domain for the specified TLD
    .DESCRIPTION Retrieve the schema to be submitted when registering a Domain for the specified TLD
    .PARAMETER
    #>
    param(
        [parameter()]$Domain
    );
    ##TODO: Handle object switch of domains
    $relative_Url = "/purchase/schema/$domain"
    $header = Get-GDAuthorizationHeader
    Write-Debug "$global:GD_API_ROOT$relative_Url"
    Write-Debug $($header)
    Invoke-RestMethod -uri "$global:GD_API_ROOT$relative_Url" -headers $header
}

#GET /v1/domains/suggest 
#Suggest alternate Domain names based on a seed Domain, a set of keywords, or the shopper's purchase history
function Get-GDSuggestedDomains
{
    <#
    .SYNOPSIS Suggest alternate Domain names based on a seed Domain, a set of keywords, or the shopper's purchase history
    .DESCRIPTION Suggest alternate Domain names based on a seed Domain, a set of keywords, or the shopper's purchase history
    #>
    param(
        [parameter(mandatory=$true)]$query,
        [parameter()][string[]]$tlds
    );
    #TODO: Add ValidateSets and all additional parameters to this function
    $relative_Url = "/suggest?query=$query"
    if($tlds)
    {
        $relative_Url += "&tlds=$($tlds -join ",")"
    }
    $header = Get-GDAuthorizationHeader
    Write-Debug "$global:GD_API_ROOT$relative_Url"
    Write-Debug $($header)
    Invoke-RestMethod -uri "$global:GD_API_ROOT$relative_Url" -headers $header
}

#GET /v1/domains/tlds
# Retrieves a list of TLDs supported and enabled for sale
function Get-GDTLDList
{
    <#
    .SYNOPSIS Retrieves a list of TLDs supported and enabled for sale
    .DESCRIPTION Retrieves a list of TLDs supported and enabled for sale
    #>
    param(
    );
    $relative_Url = "/tlds"
    $header = Get-GDAuthorizationHeader
    Write-Debug "$global:GD_API_ROOT$relative_Url"
    Write-Debug $($header)
    Invoke-RestMethod -uri "$global:GD_API_ROOT$relative_Url" -headers $header
}