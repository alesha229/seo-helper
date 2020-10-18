<?php



$HOST = 'localhost';
$USER = 'u0491_zeuslabgq';
$PASS = '9l#U9ly9';
$BASE = 'u0491157_zeuslabgq';



$db = mysqli_connect("$HOST","$USER","$PASS","$BASE");
if(!$db){exit('Error 0x24.');}
mysqli_set_charset($db,'utf8');



////////////////////////////////////////////////////////////////
// tables : site_checks
// tables : site_prices
// tables : site_users
// tables : site_users_site
///////////////////////////////////////////////////////////////

class Site

{
    function checksite($key,$ip,$username)
    {

        global $db;



















        $query = "SELECT * FROM ce_key WHERE key = $key and isactivate = '0' LIMIT 1";

        $result = mysqli_query($db, $query);

        $row = mysqli_fetch_assoc($result);

        if($row == null){return true;}

        if($row != null){return false;}

    }


}

class Auth

{

    function CheckUser($username , $password, $hwid)
    {

        global $db;

        $username = htmlspecialchars(mysqli_escape_string($db, $username));

        $password = sha1(htmlspecialchars(mysqli_escape_string($db, $password)));

        $query = "SELECT * FROM ce_users WHERE Username = '{$username}' and hash = '{$password}' LIMIT 1";

        $result = mysqli_query($db, $query);

        $row = mysqli_fetch_assoc($result);

        if($row == null){return false;}

        if($row != null){return $row;}

    }



}

class Regestration
{



    function RegisterNewUser($username , $password, $email,$ip){

        global $db;

             $username = htmlspecialchars(mysqli_escape_string($db, $username));

             $email = htmlspecialchars(mysqli_escape_string($db, $email));

             $password = sha1(htmlspecialchars(mysqli_escape_string($db, $password)));

        $time = time();

        $query = "INSERT INTO site_users (id, username, password, email,ip, date ) VALUES (NULL,'$username', '$password','$email','$ip' ,'$time')";

        mysqli_query($db, $query);

        return true;

    }

    function ValidLogin($username)
    {
        global $db;

        $username = htmlspecialchars(mysqli_escape_string($db, $username));

        $query = "SELECT * FROM site_users WHERE username = '{$username}' LIMIT 1";

        $result = mysqli_query($db, $query);

        $row = mysqli_fetch_assoc($result);

        if($row == null){return true;}
        if($row != null){return false;}
    }
    function Validmail($username,$email)
    {
        global $db;

        $email = htmlspecialchars(mysqli_escape_string($db, $email));

        $query = "SELECT * FROM site_users WHERE email = '{$email}' LIMIT 1";

        $result = mysqli_query($db, $query);

        $row = mysqli_fetch_assoc($result);

        if($row == null){return true;}
        if($row != null){return false;}
    }


}
class SEO
{
  function getsitemap($domain)
  {
	
		$domain = $domain."/robots.txt";
		$getfile = $domain; // пример URL
		$file_headers = @get_headers($getfile); // подготавливаем headers страницы

		if ($file_headers[0] == 'HTTP/1.1 404 Not Found') 
		{
			return false;

		} else if ($file_headers[0] == 'HTTP/1.1 200 OK') 
		{
		   return = true;
		}
	
  }
    function getAlexaRank($domain) {
        if(config_item('amazon_accessID') && config_item('amazon_secretKey'))
            return getAlexaRankPro($domain);
        $xml = simplexml_load_string(_curl('http://data.alexa.com/data?cli=10&dat=snbamz&url='.$domain));

        $rank['local']['country'] 	= '-';
        $rank['local']['rank'] 		= '99999999';
        $rank['global']['rank'] 	= '99999999';
        if($xml->SD[1]) {
            $rank['local']['country']	= (String)$xml->SD[1]->COUNTRY->attributes()->NAME.",".(String)$xml->SD[1]->COUNTRY->attributes()->CODE;
            $rank['local']['rank'] 	 	= (int)$xml->SD[1]->COUNTRY->attributes()->RANK;
            $rank['global']['rank']  	= (int)$xml->SD[1]->POPULARITY->attributes()->TEXT;
            if(!$rank['local']['rank'] || $rank['local']['rank'] == 0)
            {
                $rank['local']['rank']	 	= $rank['global']['rank'];
                $rank['local']['country']	= 'Global';
            }
        }
        return $rank;
    }

    function getAlexaRankPro($domain){
        $CI     =& get_instance();
        $accessKeyId = config_item('amazon_accessID');;
        $secretAccessKey = config_item('amazon_secretKey');;
        $CI->load->library("alexa");
        $urlInfo = $CI->alexa->UrlInfo($accessKeyId, $secretAccessKey, $domain);
        $info = $CI->alexa->getUrlInfo();

        $alexa['LinksInCount'] = (String)$info->Response->UrlInfoResult->Alexa->ContentData->LinksInCount;
        $alexa['global']['rank'] = (String)$info->Response->UrlInfoResult->Alexa->TrafficData->Rank;

        foreach($info->Response->UrlInfoResult->Alexa->TrafficData->RankByCountry->Country as $key => $value){

            $alexa['global']['RankByCountry'][(String)$value->attributes()["Code"]]['Rank'] = (String)$value->Rank;
            $alexa['global']['RankByCountry'][(String)$value->attributes()["Code"]]['Contribution']['PageViews'] = (String)$value->Contribution->PageViews;
            $alexa['global']['RankByCountry'][(String)$value->attributes()["Code"]]['Contribution']['Users'] = (String)$value->Contribution->Users;
        }
        foreach($info->Response->UrlInfoResult->Alexa->TrafficData->ContributingSubdomains->ContributingSubdomain as $key => $value){
            $alexa['global']['ContributingSubdomains'][] = array('url' => (String)$value->DataUrl, 'Reach' => (String)$value->Reach->Percentage,'PageViews' => (String)$value->PageViews->Percentage);

        }
        return $alexa;
    }
    function getAlexaBounceRate($domain) {

        $html_alexa = _curl('http://www.alexa.com/siteinfo/' . $domain);

        $document_alexa = new DOMDocument();

        $document_alexa->loadHTML($html_alexa);

        $selector_alexa = new DOMXPath($document_alexa);

        $content_alexa_bounce = $selector_alexa->query('/html/body//strong[@class="metrics-data align-vmiddle"]');
        $x=1;
        foreach($content_alexa_bounce as $node) {

            $doc = new DOMDocument();

            foreach ($node->childNodes as $child) {

                $doc->appendChild($doc->importNode($child, true));

            }

            $bounce_rate = $doc->saveHTML();


            if(strpos($bounce_rate, "%") !== FALSE)
                break;
            $x++;


        }

        $bounce_rate = trim(str_replace('%','', $bounce_rate));

        if(is_numeric($bounce_rate))
            return $bounce_rate;

        return 0;
    }
    function getGoogleCount($domain) {
        $api_url = "http://www.google.ca/search?q=site%3A".$domain;
        $content = _curl($api_url);
        if (empty($content))
            return intval(0);
        if (!strpos($content, 'results')) return intval(0);
        $match_expression = '/About (.*?) results/sim';
        preg_match($match_expression,$content,$matches);
        if (empty($matches)) return intval(0);
        return intval(str_replace(",", "", $matches[1]));
    }

    function getYahooCount($domain) {

        $results = trim(getStringBetween(_curl("http://search.yahoo.com/search;_ylt=?p=site:" . $domain),'Next</a><span>',' results</span>'));

        $results= str_replace(",","",$results);

        if($results=="")
            return 0;
        return $results;
    }

    function getBingCount($domain) {

        $html_bing_results = _curl("http://www.bing.com/search?q=site:" . $domain . "&FORM=QBRE&mkt=en-US");

        $document = new DOMDocument();

        $document->loadHTML($html_bing_results);

        $selector = new DOMXPath($document);

        $anchors = $selector->query('/html/body//span[@class="sb_count"]');

        foreach ($anchors as $node)
        {

            $doc = new DOMDocument();

            foreach ($node->childNodes as $child) {

                $doc->appendChild($doc->importNode($child, true));

            }

            $bing_results = $doc->saveHTML();

        }

        $bing_results = str_replace("results","",$bing_results);

        $bing_results = str_replace(",","",$bing_results);

        if(trim($bing_results)!="") return $bing_results;
        return 0;

    }

    function getEfectiveUrlBK($domain)
    {
        $key = config_item("google_page_speed_key");
        $key = trim($key);
        if($key)
        {


            $domain 		= urlencode($domain);
            $lang 			= 'en';
            $contents 		= _curl("https://www.googleapis.com/pagespeedonline/v2/runPagespeed?locale=$lang&key=$key&screenshot=false&strategy=desktop&url=$domain",false,false,false,false,false,60);
            $json 			= json_decode($contents);
            if(!$json->error)
                return $json->id;
            else
                showErrorJson("Google API: ".$json->error->errors[0]->reason);

        }
        else
        {
            return array("errorMessage" => 'Google api key not found');
        }
    }
    function getSpeedData($key,$domain,$strategy='desktop',$rules =false,$timeout = 40) {


        $key = trim($key);
        $CI     =& get_instance();

        $domain = urlencode($domain);
        //$domain = urlencode($domain);
        $lang = 'en';
        $ip = $CI->input->ip_address();
        $contents = _curl("https://www.googleapis.com/pagespeedonline/v5/runPagespeed?userIp=$ip&locale=$lang&key=$key&screenshot=true&strategy=$strategy&url=$domain&&category=best-practices&category=performance&category=pwa&category=seo",false,false,false,false,false,$timeout);

        $json 	= json_decode($contents);

        if($json->responseCode == 200 || $json->responseCode == 404 || $json->responseCode == 403 || $json->captchaResult == 'CAPTCHA_NOT_NEEDED')
        {
            if(!$rules)
                return $json->ruleGroups->SPEED;
            return $json;
        }
        else
        {
            if(!$contents)
            {
                showErrorJson("Google API: Response empty");
            }
            else
            {
                showErrorJson("Google API: ".$json->error->errors[0]->reason);
            }

        }

    }





    function domainAuthority3($domain) {

        $url = 'https://seotools.iamsujoy.com/?route=bulktool';
        $fields = array(
            'getStatus' => "1",
            'sitelink' => $domain,
            'siteID' => "1",
            'da' => "1"
        );
        //url-ify the data for the POST
        foreach($fields as $key=>$value) { $fields_string .= $key.'='.$value.'&'; }
        rtrim($fields_string, '&');
        //open connection
        $ch = curl_init();
        //set the url, number of POST vars, POST data
        curl_setopt($ch,CURLOPT_URL, $url);
        curl_setopt($ch,CURLOPT_POST, count($fields));
        curl_setopt($ch,CURLOPT_POSTFIELDS, $fields_string);
        curl_setopt($ch,CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_CONNECTTIMEOUT ,10);
        curl_setopt($ch, CURLOPT_TIMEOUT, 10); //timeout in seconds

        //execute post
        $result = explode("td",curl_exec($ch));
        $da = str_ireplace("</","",$result[5]);
        $da = str_ireplace(">","",$da);
        //close connection
        curl_close($ch);
        return  intval($da);
    }
    function domainAuthority($domain)
    {
        // Get your access id and secret key here: https://moz.com/products/api/keys
        $accessID = config_item("moz_accessID");
        $secretKey = config_item("moz_secretKey");
        if(!$accessID || !$secretKey)
            return 0;
        // Set your expires times for several minutes into the future.
        // An expires time excessively far in the future will not be honored by the Mozscape API.
        $expires = time() + 300;

        // Put each parameter on a new line.
        $stringToSign = $accessID."\n".$expires;

        // Get the "raw" or binary output of the hmac hash.
        $binarySignature = hash_hmac('sha1', $stringToSign, $secretKey, true);

        // Base64-encode it and then url-encode that.
        $urlSafeSignature = urlencode(base64_encode($binarySignature));

        // Specify the URL that you want link metrics for.
        $objectURL = $domain;

        // Add up all the bit flags you want returned.
        // Learn more here: https://moz.com/help/guides/moz-api/mozscape/api-reference/url-metrics
        $cols = "103079231492";

        // Put it all together and you get your request URL.
        // This example uses the Mozscape URL Metrics API.
        $requestUrl = "http://lsapi.seomoz.com/linkscape/url-metrics/".urlencode($objectURL)."?Cols=".$cols."&AccessID=".$accessID."&Expires=".$expires."&Signature=".$urlSafeSignature;

        // Use Curl to send off your request.
        $options = array(
            CURLOPT_RETURNTRANSFER => true
        );

        $ch = curl_init($requestUrl);
        curl_setopt_array($ch, $options);
        $content = json_decode(curl_exec($ch));

        curl_close($ch);
        return $content;
    }

    function domainAuthority4($domain) {

        $url = 'http://99traffictools.com/?route=ajax';
        $fields = array(
            'mozAuthority' => "1",
            'sitelink' => $domain,
            'domainAuthority' => "1"
        );
        //url-ify the data for the POST
        foreach($fields as $key=>$value) { $fields_string .= $key.'='.$value.'&'; }
        rtrim($fields_string, '&');
        //open connection
        $ch = curl_init();
        //set the url, number of POST vars, POST data
        curl_setopt($ch,CURLOPT_URL, $url);
        curl_setopt($ch,CURLOPT_POST, count($fields));
        curl_setopt($ch,CURLOPT_POSTFIELDS, $fields_string);
        curl_setopt($ch,CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_CONNECTTIMEOUT ,10);
        curl_setopt($ch, CURLOPT_TIMEOUT, 10); //timeout in seconds

        //execute post
        $da = curl_exec($ch);
        //close connection
        curl_close($ch);
        return  intval($da);
    }


    function domainAuthorityBK($domain) {

        $url = 'http://www.seoweather.com/wp-admin/admin-ajax.php';
        $fields = array(
            'action' => "getData",
            'linkz' => $domain,
            'divid' => "1"
        );
        //url-ify the data for the POST
        foreach($fields as $key=>$value) { $fields_string .= $key.'='.$value.'&'; }
        rtrim($fields_string, '&');
        //open connection
        $ch = curl_init();
        //set the url, number of POST vars, POST data
        curl_setopt($ch,CURLOPT_URL, $url);
        curl_setopt($ch,CURLOPT_POST, count($fields));
        curl_setopt($ch,CURLOPT_POSTFIELDS, $fields_string);
        curl_setopt($ch,CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_CONNECTTIMEOUT ,10);
        curl_setopt($ch, CURLOPT_TIMEOUT, 10); //timeout in seconds

        //execute post
        $result = explode("td",curl_exec($ch));
        foreach ($result as $key => $value) {
            if(strpos($value,"dar") !== FALSE)
            {
                $da = $value;
                $da = strip_tags("<div ".stripslashes($da)."</div>");
            }
        }
        //close connection
        curl_close($ch);
        return  intval($da);
    }

    function getW3C($url)
    {
        $json = _curl("https://validator.w3.org/nu/?doc=http://$url&out=json&level=error");
        $w3c=json_decode($json);
        return count($w3c->messages);

    }
    function getBuiltWith($key,$url,$intento = 0)
    {
        //$json = _curl("https://builtwith.4p1.co/?url=$url&apikey=$key",false,false,false,false,false,15);
        $json = _curl("https://orion.apiseeds.com/api/buildwith/$url?apikey=$key",false,false,false,false,false,5);
        $response = json_decode($json);
        if(!$response->error)
        {
            return $response;
        }
        if($intento > 0)
        {
            if($response->error)
                showErrorJson("BuiltWith: ".$response->error);
            return $response;
        }else
        {
            sleep(7);
            return getBuiltWith($key,$url,1);
        }

    }
    function getWhois($key,$url)
    {
        //$json = _curl("https://whois.4p1.co/?method=domain&domain=$url&apikey=$key",false,false,false,false,false,8);
        $json = _curl("https://orion.apiseeds.com/api/whois/$url?apikey=".config_item("apiseeds_apikey"),false,false,false,false,false,8);

        $response =  json_decode($json);
        if($response->error)
            showErrorJson("Whois: ".$response->error);
        return $response;

    }
    function getSocialCount($url,$intento = 0)
    {
        //$json = _curl("https://whois.4p1.co/?method=domain&domain=$url&apikey=$key",false,false,false,false,false,8);
        $json = _curl("https://orion.apiseeds.com/api/share/count/?apikey=".config_item("apiseeds_apikey")."&url=".urlencode($url),false,false,false,false,false,5);
        //print_p($json);
        $response =  json_decode($json);
        if(!$response->error)
        {
            return $response->response->shares;
        }
        if($intento > 0){
            if($response->error)
                showErrorJson("Social Count: ".$response->error);
            return $response->response->shares;
        }else
        {
            sleep(7);
            return getSocialCount($url,1);
        }

    }
    function googleSafe($domain) {

        $results = _curl("http://www.google.com/safebrowsing/diagnostic?site=" . $domain);
        if (strpos($results,'This site is not currently listed as suspicious') !== FALSE)
            return false;
        return true;
    }

    function getStatsData($site,$technologies)
    {



        $total 		= 13;
        $warning 	= 0;
        $errors 	= 0;
        // Title
        $optimize['title'] = 'success';
        if(mb_strlen($site->metaTitle) >0 && (mb_strlen($site->metaTitle)<8 || mb_strlen($site->metaTitle)>60))
        {
            $optimize['title'] = 'warning';
            $warning++;
        }
        if(mb_strlen($site->metaTitle) == 0)
        {
            $optimize['title'] = 'error';
            $errors++;
        }


        // Description
        $optimize['description'] = 'success';
        if(mb_strlen($site->metaDescription) >0 && (mb_strlen($site->metaDescription)<10 || mb_strlen($site->metaDescription)>150))
        {
            $optimize['description'] = 'warning';
            $warning++;
        }
        if(mb_strlen($site->metaDescription) == 0)
        {
            $optimize['description'] = 'error';
            $errors++;
        }


        // Robots
        $optimize['robots'] = 'success';
        if(!$site->robots)
        {
            $optimize['robots'] = 'warning';
            $warning++;
        }

        //Sitemap
        $optimize['sitemap'] = 'success';
        if(!$site->sitemap)
        {
            $optimize['sitemap'] = 'error';
            $errors++;
        }

        //Google Indexed
        /*$optimize['googleIndex'] = 'success';
        if($site->googleIndex<100 && $site->googleIndex >=5)
        {
            $optimize['googleIndex'] = 'warning';
            $warning++;
        }
        if($site->googleIndex<5)
        {
            $optimize['googleIndex'] = 'error';
            $errors++;
        }*/

        //SSL
        $optimize['https'] = 'success';

        if(!$site->https)
        {
            $optimize['https'] = 'warning';
            $warning++;
        }

        // hasAMP
        $optimize['hasAMP'] = 'success';
        if(!$site->hasAMP)
        {
            $optimize['hasAMP'] = 'warning';
            $warning++;
        }



        // Headers
        $optimize['headers'] = 'success';
        if($site->metaH1 <1 && $site->metaH2 <1)
        {
            $optimize['headers'] = 'error';
            $errors++;
        }
        if($site->metaH1 >1 && $site->metaH2 < 1)
        {
            $optimize['headers'] = 'warning';
            $warning++;
        }

        //Google Safe Browsing
        $optimize['google_safe'] = 'success';
        if(!$site->google_safe)
        {
            $optimize['google_safe'] = 'error';
            $errors++;
        }

        //W3C
        $optimize['w3c'] = 'success';
        if($site->w3c <5 && $site->w3c > 0)
        {
            $optimize['w3c'] = 'warning';
            $warning++;
        }
        if($site->w3c > 5)
        {
            $optimize['w3c'] = 'error';
            $errors++;
        }


        //Domain Authority
        $optimize['domainAuthority'] = 'success';
        if($site->domainAuthority > 10 && $site->domainAuthority < 25)
        {
            $optimize['domainAuthority'] = 'warning';
            $warning++;
        }
        if($site->domainAuthority < 10)
        {
            $optimize['domainAuthority'] = 'error';
            $errors++;
        }

        $optimize['gzip'] = 'error';
        $errors++;
        foreach ($technologies as $key => $value) {
            if(mb_strtolower($value->name)  == 'gzip')
            {
                $optimize['gzip'] = 'success';
                $errors--;
            }

        }

        $optimize['favicon'] = 'success';
        if(trim($site->favicon) == '')
        {
            $optimize['favicon'] = 'warning';
            $warning++;
        }

        $optimize['links'] = 'success';
        $temp = json_decode($site->links);
        foreach ($temp as $key => $value) {
            if($value->error == '1')
            {
                $optimize['links'] = 'error';
                $errors++;
                break;
            }
        }








        $response['errors'] 		= intval(($errors*100)/$total);
        $response['warning']	 	= intval(($warning*100)/$total);
        $response['success'] 		= 100-($response['errors']+$response['warning']);
        $response['optimize'] 		= $optimize;

        return $response;


    }


    function getFavIcon($html)
    {
        if($html == '')
            return false;

        $doc = new DOMDocument();
        if(!$doc->loadHTML($html))
            return false;


        $xml = simplexml_import_dom($doc);
        if(!$xml)
            return false;
        $arr = $xml->xpath('//link[@rel="shortcut icon"]');
        if(!$arr[0]['href'])
        {
            $arr = $xml->xpath('//link[@rel="icon"]');
        }
        if(!$arr[0]['href'])
        {
            $arr = $xml->xpath('//link[@rel="icon shortcut"]');
        }
        return (String)$arr[0]['href'];

    }


    function getManifest($html,$url)
    {
        if($html == '')
            return false;

        $doc = new DOMDocument();
        if(!$doc->loadHTML($html))
            return false;


        $xml = simplexml_import_dom($doc);
        if(!$xml)
            return false;
        $arr = $xml->xpath('//link[@rel="manifest"]');
        $patch = (String)$arr[0]['href'];
        if($patch)
        {
            $manifest = json_decode(_curl($url.$patch));
            return $manifest;

        }
        return false;

    }

    function hasAMP($html)
    {

        if($html == '')
            return false;


        if(mb_strpos($html,"<html ⚡>") !== FALSE)
            return true;
        if(mb_strpos($html,"<html &#9889;>") !== FALSE)
            return true;
        if(mb_strpos($html,"<html amp>") !== FALSE)
            return true;
        if(mb_strpos($html,"<style amp-custom>") !== FALSE)
            return true;

        try{
            $doc = new DOMDocument();
            $doc->loadHTML($html);
            $xml = simplexml_import_dom($doc);
            if(!$xml)
                return false;
            $arr = $xml->xpath('//link[@rel="amphtml"]');
            if($arr[0]['href'])
                return true;
            return false;
        }
        catch(Exception $e)
        {
            return false;
        }
    }

    function getFacebookCount($url)
    {


        $json = json_decode(_curl("https://graph.facebook.com/?id=".urlencode($url)));
        if($json->error)
            showErrorJson("Facebook Count: ".$json->error->message);
        return intval($json->share->share_count);

    }
    function getLinkedInCount($url)
    {
        $json = json_decode(_curl("https://www.linkedin.com/countserv/count/share?url=".urlencode($url)."&format=json"));

        return intval($json->count);
    }
    function getPinterestCount($url)
    {
        $json = json_decode(_curl("http://api.pinterest.com/v1/urls/count.json?callback=receiveCount&url=".urlencode($url)));
        return intval($json->receiveCount->count);
    }
    function getStumbleuponCount($url)
    {
        $json = json_decode(_curl("http://www.stumbleupon.com/services/1.01/badge.getinfo?url=".urlencode($url)));
        return intval($json->result->views);
    }
    function getGooglePlusCount($url)
    {
        $post ='[{"method":"pos.plusones.get","id":"p","params":{"nolog":true,"id":"' . $url . '","source":"widget","userId":"@viewer","groupId":"@self"},"jsonrpc":"2.0","key":"p","apiVersion":"v1"}]';
        $json = json_decode(_curl("https://clients6.google.com/rpc?key=AIzaSyCKSbrvQasunBoV16zDH9R33D88CeLr9gQ",$post,false,true));

        return intval($json[0]->result->metadata->globalCounts->count);

    }
    function inHX($html,$string,$hx = "h1")
    {
        $h1 = getTextBetweenTags(mb_strtolower($html),$hx);

        foreach ($h1 as $key => $value) {
            if(mb_strpos($value, $string) !== FALSE)
                return true;
        }
        return false;

    }


    ///////////


    function LookupDomain($domain){
        global $whoisservers;
        $domain_parts = explode(".", $domain);
        $tld = strtolower(array_pop($domain_parts));
        $whoisserver = $whoisservers[$tld];
        if(!$whoisserver) {
            return "Error: No appropriate Whois server found for $domain domain!";
        }
        $result = QueryWhoisServer($whoisserver, $domain);
        if(!$result) {
            return "Error: No results retrieved from $whoisserver server for $domain domain!";
        }
        else {
            while(strpos($result, "Whois Server:") !== FALSE){
                preg_match("/Whois Server: (.*)/", $result, $matches);
                $secondary = $matches[1];
                if($secondary) {
                    $result = QueryWhoisServer($secondary, $domain);
                    $whoisserver = $secondary;
                }
            }
        }
        $temp = explode("\n", $result);
        foreach ($temp as $key => $value) {
            $a = explode(":",$value);
            $a[0] =ltrim(str_ireplace(">", "",$a[0]));
            $response[mb_strtolower($a[0])] = ltrim($a[1]);
        }
        return $response;
    }

    function LookupIP($ip) {
        $whoisservers = array(
            //"whois.afrinic.net", // Africa - returns timeout error :-(
            "whois.lacnic.net", // Latin America and Caribbean - returns data for ALL locations worldwide :-)
            "whois.apnic.net", // Asia/Pacific only
            "whois.arin.net", // North America only
            "whois.ripe.net" // Europe, Middle East and Central Asia only
        );
        $results = array();
        foreach($whoisservers as $whoisserver) {
            $result = QueryWhoisServer($whoisserver, $ip);
            if($result && !in_array($result, $results)) {
                $results[$whoisserver]= $result;
            }
        }
        $res = "RESULTS FOUND: " . count($results);
        foreach($results as $whoisserver=>$result) {
            $res .= "\n\n-------------\nLookup results for " . $ip . " from " . $whoisserver . " server:\n\n" . $result;
        }
        return $res;
    }

    function ValidateIP($ip) {
        $ipnums = explode(".", $ip);
        if(count($ipnums) != 4) {
            return false;
        }
        foreach($ipnums as $ipnum) {
            if(!is_numeric($ipnum) || ($ipnum > 255)) {
                return false;
            }
        }
        return $ip;
    }

    function ValidateDomain($domain) {
        if(!preg_match("/^([-a-z0-9]{2,100})\.([a-z\.]{2,8})$/i", $domain)) {
            return false;
        }
        return $domain;
    }

    function QueryWhoisServer($whoisserver, $domain)
    {
        $port = 43;
        $timeout = 10;
        $fp = @fsockopen($whoisserver, $port, $errno, $errstr, $timeout) or die("Socket Error " . $errno . " - " . $errstr);
        if($whoisserver == "whois.verisign-grs.com") $domain = "domain ".$domain; // whois.verisign-grs.com needs to be proceeded by the keyword "domain ", otherwise it will return any result containing the searched string.
        fputs($fp, $domain . "\r\n");
        $out = "";
        while(!feof($fp)){
            $out .= fgets($fp);
        }
        fclose($fp);

        $res = "";
        if((strpos(strtolower($out), "error") === FALSE) && (strpos(strtolower($out), "not allocated") === FALSE)) {
            $rows = explode("\n", $out);
            foreach($rows as $row) {
                $row = trim($row);
                if(($row != '') && ($row{0} != '#') && ($row{0} != '%')) {
                    $res .= $row."\n";
                }
            }
        }
        return $res;
    }
    function PR_getProcess()
    {

        $process[] = array('title' => __("Crawling website"), 'action' => 'crawl','description' => __('Downloading website content to analyze and evaluate.'));
        $process[] = array('async' => true,'title' => __("Google Pagespeed Desktop"), 'action' => 'pagespeed','description' => __('We built this Website (Desktop) Speed Test to help you analyze the load speed of your websites and learn how to make them faster'));
        $process[] = array('title' => __("Calculating Traffics"), 'action' => 'traffic','description' => __('We strive to provide useful information for website owners, buyers, competitors and anyone else looking for estimated visitor quantities and web analytics'));
        $process[] = array('title' => __("Counting Social Data"), 'action' => 'social','description' => __('Fetching all social networks (Facebook, Google Plus, StumbleUpOn, LinkedIn, More...)'));
        $process[] = array('title' => __("Analyzing Technologies"), 'action' => 'technologies','description' => __('Covers 20,000+ internet technologies which include analytics, advertising, hosting, CMS and many more'));
        $process[] = array('title' => __("Bounce Rate"), 'action' => 'bouncerate','description' => __('Bounce rates can be used to help determine the effectiveness or performance of an entry page at generating the interest of visitors. An entry page with a low bounce rate means that the page effectively causes visitors to view more pages and continue on deeper into the web site.'));
        $process[] = array('title' => __("Available Domains (TDL)"), 'action' => 'available_domain','description' => __('Checking if are available similar names domains'));
        $process[] = array('async' => true,'title' => __("Google Pagespeed Mobile"), 'action' => 'pagespeedm','description' => __('We built this Website (Mobile) Speed Test to help you analyze the load speed of your websites and learn how to make them faster'));
        $process[] = array('title' => __("Domain Authority"), 'action' => 'da','description' => __('Domain Authority is a score (on a 100-ing/point scale) developed by Moz that predicts how well a website will rank on search engines.'));
        $process[] = array('title' => __("Validating W3C"), 'action' => 'w3c','description' => __('W3C standards define an Open Web Platform for application development that has the unprecedented potential to enable developers to build rich interactive experiences, powered by vast data stores, that are available on any device'));
        $process[] = array('title' => __("Checking Blacklist Domain"), 'action' => 'google_safe','description' => __("Safe Browsing is a Google service that lets client applications check URLs against Google's constantly updated lists of unsafe web resources"));
        $process[] = array('title' => __("Searching For Broken Links"), 'action' => 'internalLinks','description' => __("Dead hyperlinks on websites are not just annoying – their existence may cause some real damage to your online business as well as to your reputation in the Internet!"));
        $process[] = array('title' => __("Getting Server Information"), 'action' => 'serverInfo','description' => __("Find out which web server is running a specific site. See information like web dedicated server name, operating system, available modules, etc."));
        $process[] = array('title' => __("DNS Records"), 'action' => 'dnsrecords','description' => __("The DNS is crucial system for today's Internet. Incorrectly set up DNS records cause many different problems to administrators of web servers and company infrastructure."));
        $process[] = array('title' => __("Server Response Details"), 'action' => 'serverresponse','description' => __("Get information regarding a specific transfer."));
        $process[] = array('title' => __("Getting whois data"), 'action' => 'whois','description' => __("Domain name lookup service to search the whois database for domain name registration information."));
        $process[] = array('title' => __("Getting manifest.json data"), 'action' => 'manifest','description' => __("The web app manifest is a simple JSON file that gives you, the developer, the ability to control how your app appears to the user in areas where they would expect to see apps (for example, a mobile device's home screen), direct what the user can launch, and define its appearance at launch."));
        $process[] = array('title' => __("Calculating Score"), 'action' => 'score','description' => __("The score is a dynamic grade on a 100-point scale that represents your Internet Marketing Effectiveness at a given time."));

        return $process;
    }

    function PR_validateDomain($url,$process,$timeout = 8)
    {

        $url = trim($url);
        $url = str_ireplace("\n", "",$url);
        $url = str_ireplace("\r", "",$url);

        $CI     =& get_instance();
        if(preg_match("#https?://#", $url) === 0)
            $url = 'http://' . $url;

        $data 	= parse_url($url);
        $domain = $data['host'];

        $domain = str_ireplace("www.", "",$domain);
        $domain = mb_strtolower($domain);
        $domain_curl = "http://".$domain;
        if($data['scheme'])
            $domain_curl = $data['scheme']."://".$domain;


        $json['domain'] = $domain;
        $json['new'] 	= TRUE;
        if(hasbadWords($domain))
        {
            unset($json['process']);
            $json['error'] = __("The domain name contains forbidden words");
        }
        else
        {
            if(is_valid_domain_name($domain_curl))
            {
                $ret = ping($domain_curl,$timeout);

                if($ret !== 404 && $ret !== 500 && $ret !== 403)
                {
                    $exist = $CI->Admin->getTable("sites",array("url" => $domain));
                    if($exist->num_rows() == 1)
                        $json['new'] = FALSE;
                    $json['process'] = $process;
                    $json['domain'] = $domain;
                    $CI->Admin->setTableIgnore("sites",array("url" => $domain,"registered" => date("Y-m-d H:i:s")));

                }
                else
                {
                    $CI->Admin->deleteTable("sites",array("url" => $domain));
                    $json['error'] = __("Your website is down or not is valid");
                }

            }
            else
            {
                $CI->Admin->deleteTable("sites",array("url" => $domain));
                $json['error'] = __("Domain not is valid");
            }
        }

        if(config_item("email_new_site") == '1')
        {
            if(!$json['error'] && $json['new'])
            {
                $ip = $CI->input->ip_address();
                $user = 'Guest';
                if(is_logged())
                    $user = _user("names")." - "._user("email");
                $message2 = "New domain registration on your site <br><br><strong>Domain: </strong>$domain<br><strong>User: </strong>$user<br><strong>IP Address: </strong>$ip";
                email(get_email_admin(),__("New domain registration"),$message2);
            }

        }
        return $json;

    }

    function PR_Process($action,$domain)
    {
        $domain = trim($domain);
        $CI     =& get_instance();
        $domain_curl 	= "http://".$domain;
        if(!is_valid_domain_name($domain_curl))
            return array("error" => __("Your website is down or not is valid"));


        switch ($action) {
            case 'crawl':
                /*if(ping($domain_curl,8))
                {
                    return array("error" => __("Your website is down or not is valid"));
                }*/



                $temp_d 					= $domain_curl;
                $domain_curl 				= getEfectiveUrl($domain_curl);


                if(substr($domain_curl, -1) == '/')
                    $domain_curl = substr($domain_curl,0,-1);



                if(!$domain_curl || $domain_curl == '://')
                    $domain_curl 			= $temp_d;
                $save['body'] 				= (_curl($domain_curl));
                $save['charset'] 			= getCharset($save['body']);

                if(mb_strtolower($save['charset']) != 'utf-8' && $save['charset'] != '')
                    $save['body'] 				= iconv($save['charset'],'UTF-8',$save['body']);
                //$save['body'] 				= mb_convert_encoding($save['body'], 'utf-8', $save['charset']);


                //$save['body'] 				= $save['body'];
                $save['headers'] 			= _curl_headers($domain_curl);

                $save['metaTitle'] 			= getMeta($save['body'],"title");
                $save['metaDescription'] 	= getMeta($save['body'],"description");
                $save['metaKeywords'] 		= getMeta($save['body'],"keywords");
                $save['metaH1'] 			= mb_substr_count($save['body'], "<h1");
                $save['metaH2'] 			= mb_substr_count($save['body'], "<h2");
                $save['metaH3'] 			= mb_substr_count($save['body'], "<h3");
                $save['metaH4'] 			= mb_substr_count($save['body'], "<h4");
                $save['favicon'] 			= getFavIcon($save['body']);
                $save['hasAMP'] 			= hasAMP($save['body']);

                $save["robots"] 			= remote_file_exists($domain_curl."/robots.txt");
                $save["sitemap"] 			= remote_file_exists($domain_curl."/sitemap.xml");

                $save['url_real'] 			= $domain_curl;



                //$domain_curl 				= trim($domain_curl);

                /*if(substr($domain_curl,-1) != '/')
                    $domain_curl = $domain_curl."/";*/

                if(!$save['body'] || strlen($save['body'])<=100)
                {
                    $save['completed'] = '1';
                    $save['score'] = '1';
                    $CI->Admin->updateTable("sites",$save,array("url" => $domain));
                    $CI->db->query("UPDATE {PRE}sites SET url=LOWER(url) WHERE url = '$domain'");
                    $return['error'] = __("Body empty!");
                    $return['next'] = true;
                }else
                {
                    $CI->Admin->updateTable("sites",$save,array("url" => $domain));
                    $CI->db->query("UPDATE {PRE}sites SET url=LOWER(url) WHERE url = '$domain'");
                    $return['message'] = __("Done!");
                }


                //unset($save['body']);
                break;
            case 'traffic':
                $alexa 						= getAlexaRank($domain);
                if(config_item('amazon_accessID') && config_item('amazon_secretKey')){
                    $save['uniqueVisitsDaily'] 	= (int)(pow($alexa['global']['rank'],-0.732)*6000000);
                    $save['pagesViewsDaily'] 	= (int)($save['uniqueVisitsDaily']*1.85);
                    $save['alexaPRO']				= json_encode($alexa);
                }else{
                    $save['alexaLocal'] 		= $alexa['local']['rank'];
                    $save['alexaLocalCountry'] 	= $alexa['local']['country'];
                    $save['alexaGlobal'] 		= $alexa['global']['rank'];
                    $save['uniqueVisitsDaily'] 	= (int)(pow($alexa['local']['rank'],-0.732)*6000000);
                    $save['pagesViewsDaily'] 	= (int)($save['uniqueVisitsDaily']*1.85);
                    $save['alexaPRO'] = '';
                }

                $CI->Admin->updateTable("sites",$save,array("url" => $domain));
                $CI->db->query("UPDATE {PRE}sites SET IncomeDaily=((uniqueVisitsDaily*0.017)*0.07) WHERE  url='$domain'");
                $CI->db->query("UPDATE {PRE}sites SET IncomeDaily=(IncomeDaily*1.5) WHERE alexaLocal <= 1000 AND url='$domain'");
                $CI->db->query("UPDATE {PRE}sites SET IncomeDaily=(IncomeDaily*2) WHERE alexaLocal <= 100 AND url='$domain'");
                $return['message'] = __("Done!");
                break;
            case 'social':
                $site 	= $CI->Admin->getTable("sites",array("url" => $domain))->row();
                $social = getSocialCount($site->url_real);

                /*$social['facebook'] = getFacebookCount($site->url_real);
                $social['linkedin'] = getLinkedInCount($site->url_real);
                $social['pinterest'] = getPinterestCount($site->url_real);
                $social['stumbleupon'] = getStumbleuponCount($site->url);
                $social['google_plus'] = getGooglePlusCount($site->url_real);*/


                $CI->db->query("UPDATE {PRE}sites SET social='".json_encode($social)."' WHERE url='$domain'");
                $return['message'] = __("Done!");
                break;
            case 'whois':
                $site 	= $CI->Admin->getTable("sites",array("url" => $domain))->row();
                if(config_item("apiseeds_apikey"))
                {
                    $days		= getDaysDiff($site->updated,date("Y-m-d H:i:s"));
                    if($days>=5 || !$site->whois)
                    {
                        $whois 						= getWhois('',$domain);
                        if($whois->success)
                        {
                            $CI->Admin->updateTable("sites",array("whois" => json_encode($whois->response)),array("url" => $domain));
                        }
                        else
                        {
                            setLog('whois',$whois->error);
                        }



                    }
                }
                else
                {
                    showErrorJson("Google API: API Not found");
                }
                $return['message'] = __("Done!");
                break;
            case 'technologies':



                if(config_item("apiseeds_apikey"))
                {

                    $site_obj 	= $CI->Admin->getTable("sites",array("url" => $domain));
                    $site_t 	= $CI->Admin->getTable("technologies",array("url" => $domain));
                    $site 		= $site_obj->row();
                    //$domain 	= $site->url_real;
                    $days		= getDaysDiff($site->updated,date("Y-m-d H:i:s"));
                    if($days>0 || $site_t->num_rows() == 0)
                    {
                        $technologies 		= getBuiltWith(config_item("apiseeds_apikey"),$domain);
                        if($technologies->success)
                        {

                            $CI->Admin->deleteTable("technologies",array("url" => $domain));
                            $save 			= array();
                            foreach ($technologies->response->technologies as $key => $value) {

                                $save[$key]["url"] 		= $domain;
                                $save[$key]["name"] 	= $value->name;
                                $save[$key]["icon"] 	= $value->icon_png;
                                $save[$key]["tag1"] 	= $value->cats[0];
                                $save[$key]["tag2"] 	= $value->cats[1];

                            }
                            $CI->Admin->setTable("technologies",$save,true);
                            $return['message'] = __("Done!");
                        }
                        else
                        {
                            setLog('technologies',$technologies->error);
                            $return['error'] = __("Empty response");
                        }
                    }
                    else
                    {
                        $return['message'] = __("Done!");
                    }



                }else
                {
                    showErrorJson("Technologies: API Not found");
                }
                break;
            case 'engine':
                $save["googleIndex"] 	= intval(getGoogleCount($domain));
                $save["yahooIndex"] 	= intval(getYahooCount($domain));
                $save["bingIndex"] 		= intval(getBingCount($domain));


                $CI->Admin->updateTable("sites",$save,array("url" => $domain));
                break;

            case 'pagespeedm':
                $key = config_item("google_page_speed_key");
                if($key)
                {

                    $site_obj 	= $CI->Admin->getTable("sites",array("url" => $domain));
                    $site 		= $site_obj->row();
                    if($site->url_real)
                        $domain_real 	= $site->url_real;


                    $dataM 					= getSpeedData($key,$domain_real,'mobile',true);

                    $return['raw'] 			= $dataM;
                    if($dataM && !$dataM->errorMessage)
                    {
                        $save['pageSpeedMobile'] 	= json_encode($dataM);
                        $save['screenshot_mobile'] 			= getScreenshotBase64($dataM,true);
                        $CI->Admin->updateTable("sites",$save,array("url" => $domain));

                        /*$save['pagespeed_mobile'] 	= intval($dataM->ruleGroups->SPEED->score);
                        $save['pagespeed_screenshot_m'] 	= "data:".$dataM->screenshot->mime_type.";base64, ".str_ireplace(array("_","-"), array("/","+"), $dataM->screenshot->data);

                        $save['pagespeed_usability'] 	= intval($dataM->ruleGroups->USABILITY->score);
                        $save['pagespeed_rules_mobile'] 	= json_encode($dataM->formattedResults);	*/
                        $return['message'] = __("Done!");
                    }
                    else
                    {
                        $return['error'] = __("Mobile Response empty!");
                    }








                }
                else{
                    showErrorJson("Google API: API Not found");
                }
                break;

            case 'pagespeed':
                $key = config_item("google_page_speed_key");
                if($key)
                {

                    $site_obj 	= $CI->Admin->getTable("sites",array("url" => $domain));
                    $site 		= $site_obj->row();
                    if($site->url_real)
                        $domain_real 	= $site->url_real;

                    $data 					= getSpeedData($key,$domain_real,'desktop',true);
                    $return['raw'] 			= $data;

                    if($data && !$data->errorMessage)
                    {
                        if($data->title)
                        {
                            $save['metaTitle'] = $data->title;
                        }
                        $save['pageSpeedDesktop'] 			= json_encode($data);
                        $save['screenshot_desktop'] 			= getScreenshotBase64($data);
                        /*$save['pagespeed_rules'] 	= json_encode($data->formattedResults);
                        $save['pagespeed_screenshot_d'] 	= "data:".$data->screenshot->mime_type.";base64, ".str_ireplace(array("_","-"), array("/","+"), $data->screenshot->data);
                        $save['pagespeed_numberResources'] 	= intval($data->pageStats->numberResources);
                        $save['pagespeed_numberHosts'] 	= intval($data->pageStats->numberHosts);
                        $save['pagespeed_totalRequestBytes'] 	= intval($data->pageStats->totalRequestBytes);
                        $save['pagespeed_numberStaticResources'] 	= intval($data->pageStats->numberStaticResources);
                        $save['pagespeed_htmlResponseBytes'] 	= intval($data->pageStats->htmlResponseBytes);
                        $save['pagespeed_cssResponseBytes'] 	= intval($data->pageStats->cssResponseBytes);
                        $save['pagespeed_imageResponseBytes'] 	= intval($data->pageStats->imageResponseBytes);
                        $save['pagespeed_javascriptResponseBytes'] 	= intval($data->pageStats->javascriptResponseBytes);
                        $save['pagespeed_otherResponseBytes'] 	= intval($data->pageStats->otherResponseBytes);
                        $save['pagespeed_numberJsResources'] 	= intval($data->pageStats->numberJsResources);
                        $save['pagespeed_numberCssResources'] 	= intval($data->pageStats->numberCssResources);*/
                        $CI->Admin->updateTable("sites",$save,array("url" => $domain));
                        $return['message'] = __("Done!");


                    }
                    else
                    {
                        $return['error'] = __("Desktop Response empty!");
                    }







                }
                else{
                    showErrorJson("Google API: API Not found");
                }
                break;

            case 'bouncerate':
                $save['bounceRate'] 		= intval(getAlexaBounceRate($domain));
                $CI->Admin->updateTable("sites",$save,array("url" => $domain));
                $return['message'] = __("Done!");
                break;

            case 'da':

                $site_obj 	= $CI->Admin->getTable("sites",array("url" => $domain));
                $site 		= $site_obj->row();
                $days		= getDaysDiff($site->updated,date("Y-m-d H:i:s"));
                if($days>=1 || $site->pageAuthority == 0)
                {
                    $moz = domainAuthority($domain);
                    if(!$moz->status)
                    {
                        $save['domainAuthority'] 		= intval($moz->pda);
                        $save['pageAuthority'] 			= intval($moz->upa);
                        $save['mozRank'] 				= ($moz->umrp);

                        if($save['domainAuthority']>0)
                            $CI->Admin->updateTable("sites",$save,array("url" => $domain));
                        $return['message'] = 'Done!';
                    }
                    else
                    {
                        $save['error'] = $moz;
                        $return['error'] = $moz;
                        showErrorJson("Moz API: ".$moz);
                    }
                }
                else
                {
                    $return['message'] = 'Done!';
                }
                break;
            case 'w3c':
                $site_obj 	= $CI->Admin->getTable("sites",array("url" => $domain));
                $site 		= $site_obj->row();

                $save['w3c'] 		= intval(getW3C($domain));
                /*if(connect($domain, 443))
                    $save['https'] = '1'; */

                if(substr($site->url_real,0,4) == 'https')
                    $save['https'] = '1';

                if($save['https'] != '1')
                {
                    $ret = ping(str_ireplace("http://","https://",$site->url_real),5);

                    if($ret == 200)
                    {
                        $save['https'] = '1';
                    }
                }
                $CI->Admin->updateTable("sites",$save,array("url" => $domain));
                $return['message'] = 'Done!';
                break;
            case 'google_safe':
                $site_obj 	= $CI->Admin->getTable("sites",array("url" => $domain));
                $site 		= $site_obj->row();
                $save['google_safe'] 		= googleSafe($domain);
                $CI->Admin->updateTable("sites",$save,array("url" => $domain));
                //ValidateTDL($site);
                $return['message'] = 'Done!';
                break;
            case 'dnsrecords':
                $site_obj 	= $CI->Admin->getTable("sites",array("url" => $domain));
                $site 		= $site_obj->row();
                $dns = dns_get_record($site->url,DNS_A+DNS_CNAME+DNS_MX+DNS_NS+DNS_TXT+DNS_AAAA);
                $CI->Admin->updateTable("sites",array("dns_record" => json_encode($dns)),array("url" => $domain));


                $return['message'] = 'Done!';
                break;
            case 'serverresponse':
                $site_obj 	= $CI->Admin->getTable("sites",array("url" => $domain));
                $site 		= $site_obj->row();
                $ch = curl_init();
                curl_setopt($ch, CURLOPT_URL, $site->url_real);


                curl_setopt($ch, CURLOPT_CONNECTTIMEOUT ,3);
                curl_setopt($ch, CURLOPT_TIMEOUT, 3); //timeout in seconds
                curl_setopt($ch, CURLOPT_FOLLOWLOCATION, false);
                curl_setopt($ch, CURLOPT_RETURNTRANSFER,true);
                curl_setopt($ch, CURLOPT_ENCODING,'gzip');
                //curl_setopt($ch, CURLOPT_NOBODY, true);
                curl_setopt($ch, CURLOPT_HEADER,true);
                curl_setopt($ch, CURLOPT_MAX_RECV_SPEED_LARGE,100000);
                curl_exec($ch);

                if (!curl_errno($ch)) {
                    $info = curl_getinfo($ch);
                    $CI->Admin->updateTable("sites",array("curl_info" => json_encode($info)),array("url" => $domain));

                }


                curl_close($ch);

                $return['message'] = 'Done!';
                break;
            case 'manifest':
                $site_obj 	= $CI->Admin->getTable("sites",array("url" => $domain));
                $site 		= $site_obj->row();

                curl_setopt($ch, CURLOPT_URL, $site->url_real);
                $manifest = getManifest($site->body,$site->url_real);
                $CI->Admin->updateTable("sites",array("manifest" => json_encode($manifest)),array("url" => $domain));

                $return['message'] = 'Done!';
                break;
            case 'available_domain':
                $site_obj 	= $CI->Admin->getTable("sites",array("url" => $domain));
                $site 		= $site_obj->row();
                ValidateTDL($site);
                $return['message'] = 'Done!';
                break;
            case 'internalLinks':
                $site_obj 	= $CI->Admin->getTable("sites",array("url" => $domain));
                $site 		= $site_obj->row();
                $links 		= getAllLinks($site->body,$domain,20);
                foreach ($links as $key => $value)
                {

                    $ret = ping($value['link'],5);
                    $error = 0;
                    if($ret == 404 || $ret == 500 || $ret == 0)
                        $error = 1;
                    //$links_raw .= $value['link'].'|'.$value['title']."|".$ret."|".$value['rel']."|".$error.";;";
                    $links_raw[] = array("link" => $value['link'],"title" => $value['title'],"response" => $ret,"error" => $error,"rel" => $rel);
                }
                $save['links'] 		= json_encode($links_raw);
                $CI->Admin->updateTable("sites",$save,array("url" => $domain));
                $return['message'] = 'Done!';
                break;

            case 'serverInfo':
                $site_obj 			= $CI->Admin->getTable("sites",array("url" => $domain));
                $site 				= $site_obj->row();
                $ips 				= gethostbynamel($domain);
                $save['ip'] 		= implode(";",$ips);
                if($site->ip != $save['ip'] || $site->city == '')
                {
                    $ipInfo 			= getIPInfo($ips[0]);
                    $save['city']		= $ipInfo->city;
                    $save['country']	= $ipInfo->country;
                    $save['region']		= $ipInfo->regionName;
                    $save['isp']		= $ipInfo->isp;
                }








                $return['message'] = 'Done!';

                break;
            case 'score':

                $CI->db->query("UPDATE {PRE}sites SET completed=0,score=0 WHERE  url='$domain'");
                $CI->db->query("UPDATE {PRE}sites SET score=score+7 WHERE  https = 1 AND url='$domain'");
                $CI->db->query("UPDATE {PRE}sites SET score=score+10 WHERE  pageSpeed > 50 AND pageSpeed <= 80 AND url='$domain'");
                $CI->db->query("UPDATE {PRE}sites SET score=score+20 WHERE  pageSpeed > 80 AND pageSpeed <= 85 AND url='$domain'");
                $CI->db->query("UPDATE {PRE}sites SET score=score+25 WHERE  pageSpeed > 85 AND pageSpeed <= 91 AND url='$domain'");
                $CI->db->query("UPDATE {PRE}sites SET score=score+38 WHERE  pageSpeed > 91 AND pageSpeed <= 98 AND url='$domain'");
                $CI->db->query("UPDATE {PRE}sites SET score=score+50 WHERE  pageSpeed > 98 AND url='$domain'");




                $CI->db->query("UPDATE {PRE}sites SET score=score+10 WHERE  pagespeed_mobile > 91 AND url='$domain'");
                $CI->db->query("UPDATE {PRE}sites SET score=score+15 WHERE  pagespeed_mobile > 95 AND url='$domain'");

                $CI->db->query("UPDATE {PRE}sites SET score=score-5 WHERE  pagespeed_mobile < 91 AND url='$domain'");
                $CI->db->query("UPDATE {PRE}sites SET score=score-10 WHERE  pagespeed_mobile < 80 AND url='$domain'");


                $CI->db->query("UPDATE {PRE}sites SET score=score+12 WHERE  w3c > 0 AND w3c <=5 AND url='$domain'");
                $CI->db->query("UPDATE {PRE}sites SET score=score+27 WHERE  w3c = 0 AND url='$domain'");
                $CI->db->query("UPDATE {PRE}sites SET score=score+20 WHERE  (metaH1 > 0 OR metaH2 > 0) AND url='$domain'");


                // Bonus google_safe
                $CI->db->query("UPDATE {PRE}sites SET score=score+9 WHERE  google_safe = 1 AND url='$domain'");

                // Penalty google_safe
                $CI->db->query("UPDATE {PRE}sites SET score=score-50 WHERE  google_safe = 0 AND url='$domain'");

                // Bonus domainAuthority
                $CI->db->query("UPDATE {PRE}sites SET score=score+(domainAuthority/2) WHERE  domainAuthority >=50 AND url='$domain'");
                $CI->db->query("UPDATE {PRE}sites SET score=score+(domainAuthority/3) WHERE  domainAuthority >=20  AND domainAuthority < 50 AND url='$domain'");
                $CI->db->query("UPDATE {PRE}sites SET score=score+(domainAuthority/4) WHERE  domainAuthority >=10  AND domainAuthority < 20 AND url='$domain'");

                // Bonuns AMP
                $CI->db->query("UPDATE {PRE}sites SET score=score+10 WHERE  hasAMP = 1 AND url='$domain'");
                $CI->db->query("UPDATE {PRE}sites SET score=score-2 WHERE  hasAMP = 0 AND url='$domain'");

                // Bonuns manifest
                $CI->db->query("UPDATE {PRE}sites SET score=score+10 WHERE  LENGTH(manifest) >50 AND url='$domain'");


                // Penalty Title and Description
                $CI->db->query("UPDATE {PRE}sites SET score=score-5 WHERE  (CHAR_LENGTH(metaTitle)>180 OR CHAR_LENGTH(metaTitle)<5) AND url='$domain'");
                $CI->db->query("UPDATE {PRE}sites SET score=score-5 WHERE  (CHAR_LENGTH(metaDescription)>250 OR CHAR_LENGTH(metaDescription)<5) AND url='$domain'");

                // Bonus Alexa
                $CI->db->query("UPDATE {PRE}sites SET score=score+10 WHERE  score<85 AND alexaGlobal < 800 AND alexaGlobal > 0 AND url='$domain'");
                $CI->db->query("UPDATE {PRE}sites SET score=score+10 WHERE  score<85 AND alexaGlobal < 100 AND alexaGlobal > 0 AND url='$domain'");
                $CI->db->query("UPDATE {PRE}sites SET score=score+10 WHERE  score<85 AND alexaLocal < 100 AND alexaLocal > 0 AND url='$domain'");
                $CI->db->query("UPDATE {PRE}sites SET score=score+10 WHERE  alexaLocal < 10 AND alexaLocal > 0 AND url='$domain'");


                // Fixed Value
                $CI->db->query("UPDATE {PRE}sites SET score=domainAuthority-2 WHERE  domainAuthority >85 AND url='$domain'");
                $CI->db->query("UPDATE {PRE}sites SET score=0 WHERE  score < 0 AND url='$domain'");
                $CI->db->query("UPDATE {PRE}sites SET score=99 WHERE  (score >99 OR domainAuthority > 99) AND url='$domain'");





                // Penalty domainAuthority
                $CI->db->query("UPDATE {PRE}sites SET score=score-5 WHERE  score>90 AND domainAuthority < 80 AND url='$domain'");
                $CI->db->query("UPDATE {PRE}sites SET score=score-5 WHERE  score>90 AND domainAuthority < 90 AND url='$domain'");
                $CI->db->query("UPDATE {PRE}sites SET score=score-10 WHERE  score>80 AND domainAuthority < 10 AND url='$domain'");


                // Penalty Index Google
                //$CI->db->query("UPDATE {PRE}sites SET score=score-10 WHERE  googleIndex < 10 AND url='$domain'");


                // Fixed Value
                $CI->db->query("UPDATE {PRE}sites SET score=2+(domainAuthority/2) WHERE  score <= 0 AND url='$domain'");
                $CI->db->query("UPDATE {PRE}sites SET score=99 WHERE  (score >99 OR domainAuthority > 99) AND url='$domain'");
                $CI->db->query("UPDATE {PRE}sites SET url_real=url WHERE  url_real = '' AND url='$domain'");



                // Completed
                $CI->db->query("UPDATE {PRE}sites SET completed=1 WHERE url='$domain'");


                // Save history
                if(config_item("save_historical") == '1')
                {
                    $site_obj 	= $CI->db->query("SELECT COUNT(*) AS total FROM {PRE}site_history WHERE created between '".date("Y-m-d")." 00:00:00' AND '".date("Y-m-d")." 23:59:59' AND url='$domain'")->row();
                    if($site_obj->total == 0)
                    {
                        $site_obj 	= $CI->Admin->getTable("sites",array("url" => $domain))->row();
                        $site_t 	= $CI->Admin->getTable("technologies",array("url" => $domain))->result();
                        $save = array();
                        $save['url'] = $domain;
                        $save['data'] = json_encode($site_obj);
                        $save['technologies'] = json_encode($site_t);
                        $CI->Admin->setTableIgnore("site_history",$save);
                        unset($save);
                    }
                }


                if(config_item("email_update_site") == '1')
                {

                    $ip = $CI->input->ip_address();
                    $user = 'Guest';
                    if(is_logged())
                        $user = _user("names")." - "._user("email");
                    $message2 = "New domain updated on your site <br><br><strong>Domain: </strong>$domain<br><strong>User: </strong>$user<br><strong>IP Address: </strong>$ip";
                    email(get_email_admin(),__("New domain updated"),$message2);


                }



                $return['message'] = 'Done!';

                break;

            default:
                # code...
                break;
        }

        return $return;
    }

    function ValidateTDL($site)
    {
        $CI     =& get_instance();
        $tdl = array("co","us","com","org","net");
        $temp =explode(".", $site->url);
        unset($temp[count($temp)-1]);
        $domain = '';
        $domain = implode(".",$temp);

        foreach ($tdl as $key => $value) {
            $domain_OK = $domain.".".$value;

            $domains_list[] = $domain_OK;


        }


        $order=array('q','a','z','w','s','x','e','d','c','r','f','v','t','g','b','y','h','n','u','j','m','i','k','o','l','p');

        $domain = substr($site->url,1);

        foreach ($order as $key => $value) {
            if($value == $site->url[0])
            {

                //$order2[] = $order[$key-3];
                //$order2[] = $order[$key-2];
                $order2[] = $order[$key-1];
                $order2[] = $order[$key+1];
                //$order2[] = $order[$key+2];
                //$order2[] = $order[$key+3];

            }
        }


        $domainSplit = str_split($site->url);
        unset($domainSplit[1]);
        $domain_OK = implode("", $domainSplit);

        $domains_list[] = $domain_OK;




        foreach ($order2 as $key => $value) {
            if($value)
            {
                $domain_OK = $value.$domain;
                $domains_list[] = $domain_OK;


            }
        }

        foreach ($domains_list as $key => $value) {
            //$whois[$value] 	= getWhois('',$value);
            if ( checkdnsrr($value, 'ANY') ) {
                $response = array("success" => true);
            }
            else {
                $response = array("success" => false);
            }
            $whois[$value] 	= $response;
            //sleep(rand(0,1));
        }



        $CI->Admin->updateTable("sites",array("available_domain" => json_encode($whois)),array("url" => $site->url));





    }

}

?>