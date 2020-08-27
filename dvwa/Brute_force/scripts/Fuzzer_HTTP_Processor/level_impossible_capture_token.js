var count = 1;

function processMessage(utils, message) {

	// Process fuzzed message...
	var TreeSet = Java.type("java.util.TreeSet")
	var HtmlParameter = Java.type("org.parosproxy.paros.network.HtmlParameter")
	var URLEncoder = Java.type("java.net.URLEncoder");
	
	user_token = org.zaproxy.zap.extension.script.ScriptVars.getGlobalVar("gvar.user_token");
	if (user_token == null)
		user_token = "";
	
	
	print("Process fuzzed message::user_token :: " + user_token);
	print("message.getFormParams()::"+message.getFormParams());
	
	p = new TreeSet();
	
	var it = message.getFormParams().iterator();

	while(it.hasNext()){
		param = it.next()
		var val = param.getValue();
		if (param.getName().equals("user_token")){
			val = URLEncoder.encode(user_token, "UTF-8");
		}
		
		p.add(new HtmlParameter(HtmlParameter.Type.form, param.getName(), val));
	}
	
	message.setFormParams(p)
	print("message.getRequestHeader():: " + message.getRequestHeader());
	print("message.getRequestBody():: " + message.getRequestBody());
}

function processResult(utils, fuzzResult){
	var Matcher = Java.type("java.util.regex.Matcher");
	var Pattern = Java.type("java.util.regex.Pattern");
	
	var srchptrn = '<input type=\'hidden\' name=\'user_token\' value=\'([^\']+)\' />';
	var sstring = fuzzResult.getHttpMessage().getResponseBody().toString();

	print ("getResponseHeader():: " + fuzzResult.getHttpMessage().getResponseHeader());

	r = Pattern.compile(srchptrn);
	m = r.matcher(sstring);
	var user_token = "";

	if(m.find()){
		user_token = m.group(1);
		print('found:: ' + user_token);
	}else{
		print("not found");
	}

	org.zaproxy.zap.extension.script.ScriptVars.setGlobalVar("gvar.user_token", user_token);
	return true;
} 


function getRequiredParamsNames(){
	return [];
}

function getOptionalParamsNames(){
	return [];
}

