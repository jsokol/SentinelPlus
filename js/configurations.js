function getHTTPObject() {
        var http = false;
        //Use IE's ActiveX items to load the file.
        if(typeof ActiveXObject != 'undefined') {
                try {http = new ActiveXObject("Msxml2.XMLHTTP");}
                catch (e) {
                        try {http = new ActiveXObject("Microsoft.XMLHTTP");}
                        catch (E) {http = false;}
                }
        //If ActiveX is not available, use the XMLHttpRequest of Firefox/Mozilla etc. to load the document.
        } else if (XMLHttpRequest) {
                try {http = new XMLHttpRequest();}
                catch (e) {http = false;}
        }
        return http;
}
var http = getHTTPObject();

function handler() {//Call a function when the state changes.
        if(http.readyState == 4 && http.status == 200) {
                $("txt").value = http.responseText;
        }
}

function getMethod() {
        http.open("GET", url+"?"+params, true);
        http.onreadystatechange = handler;
        http.send(null);
}

function postMethod(url,params) {
        http.open("POST", url, false);

        //Send the proper header infomation along with the request
        http.setRequestHeader("Content-type", "application/x-www-form-urlencoded");
        http.setRequestHeader("Content-length", params.length);
        http.setRequestHeader("Connection", "close");

        //http.onreadystatechange = handler;
        http.send(params);
}

function do_refresh1()
{       

        document.all.refreshScreen.style.pixelTop = (document.body.scrollTop + 50);

        document.all.refreshScreen.style.visibility="visible";

        window.setTimeout('do_refresh2()',1);

}       
 
function do_purge1()
{
        document.all.purgeScreen.style.pixelTop = (document.body.scrollTop + 50);
        document.all.purgeScreen.style.visibility="visible";
        window.setTimeout('do_purge2()',1);

}

function do_refresh2()
{       
        refresh();
        document.all.refreshScreen.style.visibility="hidden";
}       

function do_purge2()
{
        purge();
        document.all.purgeScreen.style.visibility="hidden";
}


function refresh()
{       
        var url = "configurations.php";
        var params = "REFRESH=true";

        postMethod(url,params);
} 

function purge()
{
        var url = "configurations.php";
        var params = "PURGE=true";

        postMethod(url,params);
}
