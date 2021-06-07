package accesscontrol.whitelist;

import com.apigee.flow.execution.ExecutionContext;
import com.apigee.flow.execution.ExecutionResult;
import com.apigee.flow.execution.spi.Execution;
import com.apigee.flow.message.MessageContext;
import com.apigee.flow.execution.Action;

import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.apache.commons.lang.exception.ExceptionUtils;
import org.apache.commons.net.util.SubnetUtils;
import org.json.JSONArray;
import org.json.JSONException;


public class WhiteList implements Execution {
	
	  private static final String variableReferencePatternString = "(.*?)\\{([^\\{\\} :][^\\{\\} ]*?)\\}(.*?)";
	  private static final Pattern variableReferencePattern =
	    Pattern.compile(variableReferencePatternString);
	
	private Map <String,String> properties; // read-only

    public WhiteList(Map <String,String> properties) {
            this.properties = properties;
    }
    
    private String getpropValues(MessageContext msgCtxt, String propName) throws Exception {
        String key = this.properties.get(propName);
        if (key != null) key = key.trim();
        if (key == null || key.equals("")) {
          return null;
        }
        key = resolveVariableReferences(key, msgCtxt);
        if (key == null || key.equals("")) {
          throw new IllegalStateException(propName + " resolves to null or empty.");
        }
        return key;
      }
    
    private String resolveVariableReferences(String spec, MessageContext msgCtxt) {
        Matcher matcher = variableReferencePattern.matcher(spec);
        StringBuffer sb = new StringBuffer();
        while (matcher.find()) {
          matcher.appendReplacement(sb, "");
          sb.append(matcher.group(1));
          String ref = matcher.group(2);
          String[] parts = ref.split(":",2);
          Object v = msgCtxt.getVariable(parts[0]);
          if (v != null) {
            sb.append((String) v);
          }
          else if (parts.length>1){
            sb.append(parts[1]);
          }
          sb.append(matcher.group(3));
        }
        matcher.appendTail(sb);
        return sb.toString();
      }
    
   

	public ExecutionResult execute(MessageContext messageContext, ExecutionContext executionContext) {
		
		try {
			//Initializing the flag and CIDR array
			boolean flag = false;
			JSONArray arr = null;
			String network = "";
			String ip  = "";
			
			try {
				//Get CIDR list as property (Read from KVM)
				network = getpropValues(messageContext, "CIDR");
				//Get clientIp as property (flow variable)
				ip =  getpropValues(messageContext, "ClientIP");
			} catch (Exception e) {
				throw new RuntimeException("Error Fetching prop values");
			}
			//Checking for null values
			if(network !=null && ip != null){
				 arr = new JSONArray(network);
					for(int i = 0; i < arr.length(); i++)
					   {
					    	  SubnetUtils utils = new SubnetUtils((String) arr.get(i));
					    	  if(utils.getInfo().isInRange(ip)) {
									flag = true;	
									break;
								}	
					   }
			}
			//Exception thrown in case of null values
			else{
				throw new RuntimeException("Invalid input paramaters");
			}
		   //Setting the validation result 
			messageContext.setVariable("whitelisted", flag);
	        return ExecutionResult.SUCCESS;
		
		 } catch (RuntimeException | JSONException ex) {
            ExecutionResult executionResult = new ExecutionResult(false, Action.ABORT);
            //--Returns custom error message and header
            executionResult.setErrorResponse(ex.getMessage());
            executionResult.addErrorResponseHeader("ExceptionClass", ex.getClass().getName());
            //--Sets a flow variable -- may be useful for debugging. 
            messageContext.setVariable("JAVA_ERROR", ex.getMessage());
            messageContext.setVariable("JAVA_STACKTRACE", ExceptionUtils.getStackTrace(ex));
            return executionResult;
        }
		
		
	}
}