var count = 1;

function processMessage(utils, message) {
	// Process fuzzed message...
	var TreeSet = Java.type("java.util.TreeSet")
	var HtmlParameter = Java.type("org.parosproxy.paros.network.HtmlParameter")
	var URLEncoder = Java.type("java.net.URLEncoder");
	
	salt = org.zaproxy.zap.extension.script.ScriptVars.getGlobalVar("salt.val");
	if (salt == null)
		salt = "";
	
	print("Process fuzzed message::salt :: " + salt);
	print("message.getFormParams()::"+message.getFormParams());
	
	p = new TreeSet();
	
	var it = message.getFormParams().iterator();
	while(it.hasNext()){
		param = it.next()
		var val = param.getValue();
		if (param.getName().equals("salt")){
			val = URLEncoder.encode(salt, "UTF-8");
		}
		
		p.add(new HtmlParameter(HtmlParameter.Type.form, param.getName(), val));
	}
	
	message.setFormParams(p);
	print("message.getRequestBody():: " + message.getRequestBody())
}

function processResult(utils, fuzzResult){
	var Matcher = Java.type("java.util.regex.Matcher");
	var Pattern = Java.type("java.util.regex.Pattern");
	
	var srchptrn =  '<input type="hidden" id="salt" name="salt" value="([^"]+)" />';
	var sstring = fuzzResult.getHttpMessage().getResponseBody().toString();
	
	r = Pattern.compile(srchptrn);
	m = r.matcher(sstring);
	var salt = "";
	if(m.find()){
		salt = m.group(1);
		print('found:: ' + salt);
	}else{
		print("not found");
	}

	org.zaproxy.zap.extension.script.ScriptVars.setGlobalVar("salt.val", salt);
	return true;
}


function getRequiredParamsNames(){
	return [];
}

function getOptionalParamsNames(){
	return [];
}

