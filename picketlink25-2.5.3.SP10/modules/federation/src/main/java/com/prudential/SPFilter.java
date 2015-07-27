/*
 * JBoss, Home of Professional Open Source
 *
 * Copyright 2013 Red Hat, Inc. and/or its affiliates.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.prudential;

import org.jboss.logging.Logger;
import org.picketlink.common.ErrorCodes;
import org.picketlink.common.constants.GeneralConstants;
import org.picketlink.common.constants.JBossSAMLURIConstants;
import org.picketlink.common.exceptions.ConfigurationException;
import org.picketlink.common.exceptions.ParsingException;
import org.picketlink.common.exceptions.ProcessingException;
import org.picketlink.common.exceptions.TrustKeyConfigurationException;
import org.picketlink.common.exceptions.TrustKeyProcessingException;
import org.picketlink.common.exceptions.fed.AssertionExpiredException;
import org.picketlink.common.exceptions.fed.IssuerNotTrustedException;
import org.picketlink.common.util.DocumentUtil;
import org.picketlink.common.util.StringUtil;
import org.picketlink.config.federation.AuthPropertyType;
import org.picketlink.config.federation.KeyProviderType;
import org.picketlink.config.federation.PicketLinkType;
import org.picketlink.config.federation.SPType;
import org.picketlink.config.federation.TrustType;
import org.picketlink.config.federation.handler.Handlers;
import org.picketlink.identity.federation.api.saml.v2.request.SAML2Request;
import org.picketlink.identity.federation.api.saml.v2.response.SAML2Response;
import org.picketlink.identity.federation.api.saml.v2.sig.SAML2Signature;
import org.picketlink.identity.federation.core.interfaces.ProtocolContext;
import org.picketlink.identity.federation.core.interfaces.TrustKeyManager;
import org.picketlink.identity.federation.core.saml.v2.common.IDGenerator;
import org.picketlink.identity.federation.core.saml.v2.common.SAMLDocumentHolder;
import org.picketlink.identity.federation.core.saml.v2.factories.SAML2HandlerChainFactory;
import org.picketlink.identity.federation.core.saml.v2.holders.DestinationInfoHolder;
import org.picketlink.identity.federation.core.saml.v2.holders.IssuerInfoHolder;
import org.picketlink.identity.federation.core.saml.v2.impl.DefaultSAML2HandlerChainConfig;
import org.picketlink.identity.federation.core.saml.v2.impl.DefaultSAML2HandlerRequest;
import org.picketlink.identity.federation.core.saml.v2.impl.DefaultSAML2HandlerResponse;
import org.picketlink.identity.federation.core.saml.v2.interfaces.SAML2Handler;
import org.picketlink.identity.federation.core.saml.v2.interfaces.SAML2Handler.HANDLER_TYPE;
import org.picketlink.identity.federation.core.saml.v2.interfaces.SAML2HandlerChain;
import org.picketlink.identity.federation.core.saml.v2.interfaces.SAML2HandlerChainConfig;
import org.picketlink.identity.federation.core.saml.v2.interfaces.SAML2HandlerRequest;
import org.picketlink.identity.federation.core.saml.v2.interfaces.SAML2HandlerRequest.GENERATE_REQUEST_TYPE;
import org.picketlink.identity.federation.core.saml.v2.interfaces.SAML2HandlerResponse;
import org.picketlink.identity.federation.core.saml.v2.util.AssertionUtil;
import org.picketlink.identity.federation.core.saml.v2.util.HandlerUtil;
import org.picketlink.identity.federation.core.util.CoreConfigUtil;
import org.picketlink.identity.federation.core.util.XMLSignatureUtil;
import org.picketlink.identity.federation.saml.v2.SAML2Object;
import org.picketlink.identity.federation.saml.v2.assertion.AssertionType;
import org.picketlink.identity.federation.saml.v2.assertion.AttributeStatementType;
import org.picketlink.identity.federation.saml.v2.assertion.AttributeStatementType.ASTChoiceType;
import org.picketlink.identity.federation.saml.v2.assertion.AttributeType;
import org.picketlink.identity.federation.saml.v2.assertion.NameIDType;
import org.picketlink.identity.federation.saml.v2.assertion.SubjectType;
import org.picketlink.identity.federation.saml.v2.protocol.AuthnRequestType;
import org.picketlink.identity.federation.saml.v2.protocol.LogoutRequestType;
import org.picketlink.identity.federation.saml.v2.protocol.RequestAbstractType;
import org.picketlink.identity.federation.saml.v2.protocol.ResponseType;
import org.picketlink.identity.federation.saml.v2.protocol.StatusResponseType;
import org.picketlink.identity.federation.saml.v2.protocol.StatusType;
import org.picketlink.identity.federation.web.core.HTTPContext;
import org.picketlink.identity.federation.web.interfaces.IRoleValidator;
import org.picketlink.identity.federation.web.roles.DefaultRoleValidator;
import org.picketlink.identity.federation.web.util.ConfigurationUtil;
import org.picketlink.identity.federation.web.util.PostBindingUtil;
import org.w3c.dom.Document;
import org.w3c.dom.Node;
import org.xml.sax.SAXException;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.RequestDispatcher;
import javax.servlet.ServletContext;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import javax.xml.crypto.MarshalException;
import javax.xml.crypto.dsig.CanonicalizationMethod;
import javax.xml.crypto.dsig.XMLSignatureException;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.MalformedURLException;
import java.net.URL;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.Principal;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;

import static org.picketlink.common.util.StringUtil.isNotNull;

/**
 * A service provider filter for web container agnostic providers
 *
 * @author Anil.Saldhana@redhat.com
 * @since Aug 21, 2009
 */
public class SPFilter implements Filter {

	public static long limitSeconds = 60000; //86400000
	
    private static Logger log = Logger.getLogger(SPFilter.class);

    private final boolean trace = log.isTraceEnabled();
    
    final static String IMAGE_PATTERN = "([^\\s]+(\\.(?i)(jpg|png|gif|bmp|js|css))$)";
    
	final static Pattern pattern = Pattern.compile(IMAGE_PATTERN);

    protected SPType spConfiguration = null;

    protected PicketLinkType picketLinkConfiguration = null;

    protected String configFile = GeneralConstants.CONFIG_FILE_LOCATION;
    
    protected String SID_CONST = "sid";

    protected String serviceURL = null;

    protected String identityURL = null;

    private TrustKeyManager keyManager;

    private ServletContext context = null;

    private transient SAML2HandlerChain chain = null;

    protected boolean ignoreSignatures = false;

    private IRoleValidator roleValidator = new DefaultRoleValidator();
    
    private List<String> excludedURLs = new ArrayList<String>();

    private String logOutPage = GeneralConstants.LOGOUT_PAGE_NAME;
    
    private final String SSO_FLAG_CONST = "SSOFlag";
    
    private final static String SSO_Y = "Y";
    private final static String SSO_N = "N";
    private final static String SOURCE = "source";
    private String sso_flag = SSO_Y;
    
    private String session_id_param;
    private String sid_param;
    private String pse_landing;
    
    private final static String PSE = "PSE";
    
    //private boolean start = true;
    //private long startTime = 0;

    protected String canonicalizationMethod = CanonicalizationMethod.EXCLUSIVE_WITH_COMMENTS;

    public void destroy() {
    }

    public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain)
            throws IOException, ServletException {
        HttpServletRequest request = (HttpServletRequest) servletRequest;
        HttpServletResponse response = (HttpServletResponse) servletResponse;

        boolean postMethod = "POST".equalsIgnoreCase(request.getMethod());

        HttpSession session = request.getSession();
        
        log.info("running sp filter....");
        
        //Principal userPrincipal = null;
        //if(session.getAttribute(GeneralConstants.PRINCIPAL_ID)!=null)
        //	userPrincipal = (Principal) session.getAttribute(GeneralConstants.PRINCIPAL_ID);
        //log.info("userPrincipal="+userPrincipal+", "+spConfiguration.getServiceURL());
        
        
        String samlRequest = request.getParameter(GeneralConstants.SAML_REQUEST_KEY);
        String samlResponse = request.getParameter(GeneralConstants.SAML_RESPONSE_KEY);
        
        String session_value = request.getParameter(sid_param);
        String sso_status = (request.getParameter(SSO_FLAG_CONST) == null) 
        						? sso_flag : request.getParameter(SSO_FLAG_CONST);

        String source = null; 
        if(session.getAttribute(SOURCE)==null) {
        	if(request.getParameter(SOURCE)!=null || pse_landing.equals("Y"))
        	   session.setAttribute(SOURCE, PSE);
        }
        
        if(session.getAttribute(SOURCE)!=null)
            source = (String) session.getAttribute(SOURCE);
         
         System.out.println("source="+source);
        
        //String fullPath = request.getRequestURL().toString();
        //log.info("request_url=" + fullPath);
    	//String url_param = request.getParameter("url");
    	
    	//log.info("limitSeconds="+limitSeconds);
        
    	// local logout
    	String lloStr = request.getParameter(GeneralConstants.LANDING_PAGE);
        boolean llogoutRequest = isNotNull(lloStr) && "true".equalsIgnoreCase(lloStr);
        if (llogoutRequest) {
        	return;
        }
    	
        
        /*
    	if (checkUrlsExcluded(excludedURLs, request.getRequestURI())) {
    		if (isNotNull(url_param)) {
        		request.getRequestDispatcher(url_param).forward(request, response);
        	} else {
        		filterChain.doFilter(request, response);
        	}
            return;
        }
    	
    	if (session_value != null || sso_status.equals(SSO_N)) {
        	if (isNotNull(url_param)) {
        		request.getRequestDispatcher(url_param).forward(request, response);
        	} else {
        		filterChain.doFilter(servletRequest, servletResponse);
        	}
    		return;
    	}*/
        
        if (checkUrlsExcluded(excludedURLs, request.getRequestURI()) || session_value != null || (source==null && sso_status.equals(SSO_N)) 
        		|| validateExtension(request.getRequestURI()) || validateAdminUrl(session, request.getRequestURL().toString())) {
        	filterChain.doFilter(servletRequest, servletResponse);
    		return;
        }
    	
        // Eagerly look for Global LogOut
        String gloStr = request.getParameter(GeneralConstants.GLOBAL_LOGOUT);
        boolean logOutRequest = isNotNull(gloStr) && "true".equalsIgnoreCase(gloStr);
        if (!postMethod && !logOutRequest) {
            // Check if we are already authenticated
            //if (userPrincipal != null) {
            	/*StringBuffer sb = request.getRequestURL().append('?').append(request.getQueryString());
            	List<String> blacklist=(List<String>) session.getAttribute("blacklist");
            	if (blacklist == null || !blacklist.contains(sb.toString())) {*/
            	
            	    /*
            		if (isNotNull(url_param)) {
	            		request.getRequestDispatcher(url_param).forward(request, response);
	            	} else {
	            		filterChain.doFilter(servletRequest, servletResponse);
	            	}
	            	*/
            	//filterChain.doFilter(servletRequest, servletResponse);
            	//return;
            	
            	/*} else {
            		SAML2HandlerResponse saml2HandlerResponse = new DefaultSAML2HandlerResponse();
            		saml2HandlerResponse.setError(403, "User Principal not determined: Forbidden");
            		response.sendError(saml2HandlerResponse.getErrorCode());
            	}*/

            //} else {
            	// We need to send request to IDP
		        String relayState = null;
		        try {
		        	/*if (isNotNull(url_param)) {
		        		// TODO: use the handlers to generate the request
		        		StringBuffer sb = request.getRequestURL().append('?').append(request.getQueryString());
		        		AuthnRequestType authnRequest = createSAMLRequest(sb.toString(), this.serviceURL, this.identityURL);
		        		
		        		sendRequestToIDP(authnRequest, relayState, response);
		        	} else {*/
		        		// TODO: use the handlers to generate the request
			        	StringBuffer sb = request.getRequestURL();
		                if (request.getQueryString() != null) {
		                	sb.append('?').append(request.getQueryString());
		                }
		        		AuthnRequestType authnRequest = createSAMLRequest(sb.toString(), this.serviceURL, this.identityURL);
		        		sendRequestToIDP(authnRequest, relayState, response);
		        	//}
		             
		        } catch (Exception e) {
		             throw new ServletException(e);
		        }
            //}
                
            return;
            
        } else {
            if (!isNotNull(samlRequest) && !isNotNull(samlResponse)) {
            	log.info("Neither saml request nor response from IDP");
                // Neither saml request nor response from IDP
                // So this is a user request

                // Ask the handler chain to generate the saml request
                Set<SAML2Handler> handlers = chain.handlers();

                IssuerInfoHolder holder = new IssuerInfoHolder(this.serviceURL);
                ProtocolContext protocolContext = new HTTPContext(request, response, context);
                // Create the request/response
                SAML2HandlerRequest saml2HandlerRequest = new DefaultSAML2HandlerRequest(protocolContext, holder.getIssuer(),
                        null, HANDLER_TYPE.SP);

                SAML2HandlerResponse saml2HandlerResponse = new DefaultSAML2HandlerResponse();

                saml2HandlerResponse.setDestination(this.identityURL);

                // Reset the state
                try {
            		for (SAML2Handler handler : handlers) {
                        handler.reset();
                        if (saml2HandlerResponse.isInError()) {
                            response.sendError(saml2HandlerResponse.getErrorCode());
                            break;
                        }

                        if (logOutRequest || llogoutRequest) {
                            saml2HandlerRequest.setTypeOfRequestToBeGenerated(GENERATE_REQUEST_TYPE.LOGOUT);
                        } else {
                            saml2HandlerRequest.setTypeOfRequestToBeGenerated(GENERATE_REQUEST_TYPE.AUTH);
                        }
                        handler.generateSAMLRequest(saml2HandlerRequest, saml2HandlerResponse);
                    }
                } catch (ProcessingException pe) {
                    throw new RuntimeException(pe);
                }
                
                Document samlResponseDocument = saml2HandlerResponse.getResultingDocument();
                String relayState = saml2HandlerResponse.getRelayState();

                String destination = saml2HandlerResponse.getDestination();
                
                if (destination != null && samlResponseDocument != null) {
                    try {
                        this.sendToDestination(samlResponseDocument, relayState, destination, response,
                                saml2HandlerResponse.getSendRequest());
                    } catch (Exception e) {
                        if (trace)
                            log.trace("Exception:", e);
                        throw new ServletException(ErrorCodes.SERVICE_PROVIDER_SERVER_EXCEPTION + "Server Error");
                    }
                    
                    return;
                }
            }
            
            // See if we got a response from IDP
            if (isNotNull(samlResponse)) {
            	log.info("SPFilter - response from IDP");
            	
            	/*if ( start ) {
    	        	startTime = System.currentTimeMillis();
    	    		start = false;
            	}*/
            	
                boolean isValid = false;
                try {
                    isValid = this.validate(request);
                } catch (Exception e) {
                    throw new ServletException(e);
                }
                if (!isValid)
                    throw new ServletException(ErrorCodes.VALIDATION_CHECK_FAILED + "Validity check failed");

                // deal with SAML response from IDP
                byte[] base64DecodedResponse = PostBindingUtil.base64Decode(samlResponse);
                InputStream is = new ByteArrayInputStream(base64DecodedResponse);

                // Are we going to send Request to IDP?
                boolean willSendRequest = true;

                try {
                    SAML2Response saml2Response = new SAML2Response();

                    SAML2Object samlObject = saml2Response.getSAML2ObjectFromStream(is);
                    SAMLDocumentHolder documentHolder = saml2Response.getSamlDocumentHolder();
                    if (!ignoreSignatures) {
                        if (!verifySignature(documentHolder))
                            throw new ServletException(ErrorCodes.INVALID_DIGITAL_SIGNATURE + "Cannot verify sender");
                    }

                    Set<SAML2Handler> handlers = chain.handlers();
                    IssuerInfoHolder holder = new IssuerInfoHolder(request.getRequestURI().toString());
                    ProtocolContext protocolContext = new HTTPContext(request, response, context);
                    // Create the request/response
                    SAML2HandlerRequest saml2HandlerRequest = new DefaultSAML2HandlerRequest(protocolContext,
                            holder.getIssuer(), documentHolder, HANDLER_TYPE.SP);
                    if (keyManager != null)
                        saml2HandlerRequest.addOption(GeneralConstants.DECRYPTING_KEY, keyManager.getSigningKey());

                    SAML2HandlerResponse saml2HandlerResponse = new DefaultSAML2HandlerResponse();

                    // Deal with handler chains
                    for (SAML2Handler handler : handlers) {
                        if (saml2HandlerResponse.isInError()) {
                            response.sendError(saml2HandlerResponse.getErrorCode());
                            break;
                        }
                        if (samlObject instanceof RequestAbstractType) {
                            handler.handleRequestType(saml2HandlerRequest, saml2HandlerResponse);
                            willSendRequest = false;
                        } else {
                            handler.handleStatusResponseType(saml2HandlerRequest, saml2HandlerResponse);
                        }
                    }

                    Document samlResponseDocument = saml2HandlerResponse.getResultingDocument();
                    
                    String relayState = saml2HandlerResponse.getRelayState();
                    String destination = saml2HandlerResponse.getDestination();
                    if (destination != null && samlResponseDocument != null) {
                        this.sendToDestination(samlResponseDocument, relayState, destination, response, willSendRequest);
                        return;
                    }

                    // See if the session has been invalidated
                    try {
                        session.isNew();
                    } catch (IllegalStateException ise) {
                        // we are invalidated.
                        RequestDispatcher dispatch = context.getRequestDispatcher(spConfiguration.getLogoutResponseLocation());
                        if (dispatch == null)
                            log.error("Cannot dispatch to the logout page: no request dispatcher:" + this.logOutPage);
                        else
                            dispatch.forward(request, response);
                        return;
                    }
                    
                    filterChain.doFilter(request, servletResponse);
                
                } catch (Exception e) {
                    log.error("Server Exception:", e);
                    throw new ServletException(ErrorCodes.SERVICE_PROVIDER_SERVER_EXCEPTION);
                }

            }

            if (isNotNull(samlRequest)) {
            	//resetTimeout();
            	
            	log.info("SPFilter - logout request ("+spConfiguration.getServiceURL()+")");
            	// we got a logout request
                // deal with SAML response from IDP
                byte[] base64DecodedRequest = PostBindingUtil.base64Decode(samlRequest);
                InputStream is = new ByteArrayInputStream(base64DecodedRequest);

                // Are we going to send Request to IDP?
                boolean willSendRequest = true;

                try {
                    SAML2Request saml2Request = new SAML2Request();
                    SAML2Object samlObject = saml2Request.getSAML2ObjectFromStream(is);
                    SAMLDocumentHolder documentHolder = saml2Request.getSamlDocumentHolder();

                    if (!ignoreSignatures) {
                        if (!verifySignature(documentHolder))
                            throw new ServletException(ErrorCodes.INVALID_DIGITAL_SIGNATURE + "Cannot verify sender");
                    }

                    Set<SAML2Handler> handlers = chain.handlers();
                    IssuerInfoHolder holder = new IssuerInfoHolder(this.serviceURL);
                    ProtocolContext protocolContext = new HTTPContext(request, response, context);
                    // Create the request/response
                    SAML2HandlerRequest saml2HandlerRequest = new DefaultSAML2HandlerRequest(protocolContext,
                            holder.getIssuer(), documentHolder, HANDLER_TYPE.SP);
                    if (keyManager != null)
                        saml2HandlerRequest.addOption(GeneralConstants.DECRYPTING_KEY, keyManager.getSigningKey());
                    
                    SAML2HandlerResponse saml2HandlerResponse = new DefaultSAML2HandlerResponse();
                    
                    // Deal with handler chains
                    for (SAML2Handler handler : handlers) {
                        if (saml2HandlerResponse.isInError()) {
                            response.sendError(saml2HandlerResponse.getErrorCode());
                            break;
                        }
                        if (samlObject instanceof LogoutRequestType) {
                            handler.handleRequestType(saml2HandlerRequest, saml2HandlerResponse);
                        } else {
                       	    handler.handleStatusResponseType(saml2HandlerRequest, saml2HandlerResponse);
                            willSendRequest = false;
                        }
                    }
                    
                    Document samlResponseDocument = saml2HandlerResponse.getResultingDocument();
                    String relayState = saml2HandlerResponse.getRelayState();
                    String destination = saml2HandlerResponse.getDestination();
                    if (samlResponseDocument != null && destination != null) {
                        this.sendToDestination(samlResponseDocument, relayState, destination, response, willSendRequest);
                        return;
                    }
                } catch (Exception e) {
                    if (trace)
                        log.trace("Server Exception:", e);
                    throw new ServletException(ErrorCodes.SERVICE_PROVIDER_SERVER_EXCEPTION + "Server Exception");
                }
            }
        }
    }

    public void init(FilterConfig filterConfig) throws ServletException {
        this.context = filterConfig.getServletContext();
        InputStream is = context.getResourceAsStream(configFile);

        if (is != null) {
            try {
                picketLinkConfiguration = ConfigurationUtil.getConfiguration(is);
                spConfiguration = (SPType) picketLinkConfiguration.getIdpOrSP();
            } catch (ParsingException e) {
                throw new RuntimeException(e);
            }
        } else {
            is = context.getResourceAsStream(GeneralConstants.DEPRECATED_CONFIG_FILE_LOCATION);
            if (is == null)
                throw new RuntimeException(ErrorCodes.SERVICE_PROVIDER_CONF_FILE_MISSING + configFile + " missing");
            try {
                spConfiguration = ConfigurationUtil.getSPConfiguration(is);
            } catch (ParsingException e) {
                throw new RuntimeException(e);
            }
        }

        try {
            this.identityURL = spConfiguration.getIdentityURL();
            this.serviceURL = spConfiguration.getServiceURL();
            this.canonicalizationMethod = spConfiguration.getCanonicalizationMethod();

            log.info("SPFilter:: Setting the CanonicalizationMethod on XMLSignatureUtil::" + canonicalizationMethod);
            XMLSignatureUtil.setCanonicalizationMethodType(canonicalizationMethod);

            log.trace("Identity Provider URL=" + this.identityURL);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }

        // Get the Role Validator if configured
        String roleValidatorName = filterConfig.getInitParameter(GeneralConstants.ROLE_VALIDATOR);
        if (roleValidatorName != null && !"".equals(roleValidatorName)) {
            try {
                Class<?> clazz = SecurityActions.loadClass(getClass(), roleValidatorName);
                this.roleValidator = (IRoleValidator) clazz.newInstance();
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        }

        Map<String, String> options = new HashMap<String, String>();
        String roles = filterConfig.getInitParameter(GeneralConstants.ROLES);
        if (trace)
            log.trace("Found Roles in SPFilter config=" + roles);
        if (roles != null) {
            options.put("ROLES", roles);
        }
        this.roleValidator.intialize(options);

        String samlHandlerChainClass = filterConfig.getInitParameter("SAML_HANDLER_CHAIN_CLASS");

        // Get the chain from config
        if (StringUtil.isNullOrEmpty(samlHandlerChainClass))
            chain = SAML2HandlerChainFactory.createChain();
        else
            try {
                chain = SAML2HandlerChainFactory.createChain(samlHandlerChainClass);
            } catch (ProcessingException e1) {
                throw new ServletException(e1);
            }
        try {
            // Get the handlers
            String handlerConfigFileName = GeneralConstants.HANDLER_CONFIG_FILE_LOCATION;
            Handlers handlers = null;
            if (picketLinkConfiguration != null) {
                handlers = picketLinkConfiguration.getHandlers();
            } else {
                handlers = ConfigurationUtil.getHandlers(context.getResourceAsStream(handlerConfigFileName));
            }
            chain.addAll(HandlerUtil.getHandlers(handlers));

            Map<String, Object> chainConfigOptions = new HashMap<String, Object>();
            chainConfigOptions.put(GeneralConstants.CONFIGURATION, spConfiguration);
            chainConfigOptions.put(GeneralConstants.ROLE_VALIDATOR, roleValidator);

            SAML2HandlerChainConfig handlerChainConfig = new DefaultSAML2HandlerChainConfig(chainConfigOptions);
            Set<SAML2Handler> samlHandlers = chain.handlers();

            for (SAML2Handler handler : samlHandlers) {
                handler.initChainConfig(handlerChainConfig);
            }
        } catch (Exception e) {
            throw new RuntimeException(e);
        }

        String ignoreSigString = filterConfig.getInitParameter(GeneralConstants.IGNORE_SIGNATURES);
        if (ignoreSigString != null && !"".equals(ignoreSigString)) {
            this.ignoreSignatures = Boolean.parseBoolean(ignoreSigString);
        }

        if (ignoreSignatures == false) {
            KeyProviderType keyProvider = this.spConfiguration.getKeyProvider();
            if (keyProvider == null)
                throw new RuntimeException(ErrorCodes.NULL_VALUE + "KeyProvider");
            try {
                String keyManagerClassName = keyProvider.getClassName();
                if (keyManagerClassName == null)
                    throw new RuntimeException(ErrorCodes.NULL_VALUE + "KeyManager class name");

                Class<?> clazz = SecurityActions.loadClass(getClass(), keyManagerClassName);
                this.keyManager = (TrustKeyManager) clazz.newInstance();

                List<AuthPropertyType> authProperties = CoreConfigUtil.getKeyProviderProperties(keyProvider);
                keyManager.setAuthProperties(authProperties);

                keyManager.setValidatingAlias(keyProvider.getValidatingAlias());
            } catch (Exception e) {
                log.error("Exception reading configuration:", e);
                throw new RuntimeException(e.getLocalizedMessage());
            }
            log.trace("Key Provider=" + keyProvider.getClassName());
        }

        // see if a global logout page has been configured
        String gloPage = filterConfig.getInitParameter(GeneralConstants.LOGOUT_PAGE);
        if (gloPage != null && !"".equals(gloPage)) {
            this.spConfiguration.setLogOutPage(gloPage);
            this.spConfiguration.setLogoutUrl(gloPage);
            this.spConfiguration.setLogoutResponseLocation(gloPage);
        } else {
        	this.spConfiguration.setLogOutPage(this.logOutPage);
        	this.spConfiguration.setLogoutUrl(this.logOutPage);
        	this.spConfiguration.setLogoutResponseLocation(logOutPage);
        }
        
        // get configuration session id and sid
        Enumeration<String> params = filterConfig.getInitParameterNames();
        while (params.hasMoreElements()) {
        	String pname = params.nextElement();
        	log.info(pname);
        	if (pname.equals(GeneralConstants.LOGOUT_PAGE) 
        			|| pname.equals(GeneralConstants.IGNORE_SIGNATURES) || (pname.equals("SAML_HANDLER_CHAIN_CLASS"))) {
        		continue;
        		
        	}
        	
        	if (pname.equals(GeneralConstants.ROLES) & filterConfig.getInitParameter(pname).equals(PSE)) {
                this.pse_landing="Y";
        	}
        	
        	if (pname.equals(SSO_FLAG_CONST)) {
        		this.sso_flag = (filterConfig.getInitParameter(pname) == null) 
        								? SSO_N : filterConfig.getInitParameter(pname);
        		continue;
        		
        	}

        	
        	if (pname.equals("excludedURLs")) {
        		String[] excluded = filterConfig.getInitParameter("excludedURLs").split(";");
                for (int i = 0; i < excluded.length; i++) {
                    excludedURLs.add(excluded[i]);
                }
                continue;
                
        	}
        	
        	this.session_id_param = pname;
        	this.sid_param = filterConfig.getInitParameter(pname);
        	//log.info("session_id="+this.session_id_param+",sid="+this.sid_param);
        }
    }

    /**
     * Create a SAML2 auth request
     *
     * @param serviceURL URL of the service
     * @param identityURL URL of the identity provider
     *
     * @return
     *
     * @throws ConfigurationException
     */
    private AuthnRequestType createSAMLRequest(String destUrl, String serviceURL, String identityURL) throws ConfigurationException {
        if (serviceURL == null)
            throw new IllegalArgumentException(ErrorCodes.NULL_ARGUMENT + "serviceURL");
        if (identityURL == null)
            throw new IllegalArgumentException(ErrorCodes.NULL_ARGUMENT + "identityURL");

        SAML2Request saml2Request = new SAML2Request();
        String id = IDGenerator.create("ID_");
        return saml2Request.createAuthnRequestType(id, serviceURL, identityURL, destUrl);
    }

    protected void sendRequestToIDP(AuthnRequestType authnRequest, String relayState, HttpServletResponse response)
            throws IOException, SAXException, GeneralSecurityException {
        SAML2Request saml2Request = new SAML2Request();
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        saml2Request.marshall(authnRequest, baos);

        String samlMessage = PostBindingUtil.base64Encode(baos.toString());
        String destination = authnRequest.getDestination().toASCIIString();
        
        PostBindingUtil.sendPost(new DestinationInfoHolder(destination, samlMessage, relayState), response, true);
    }

    protected void sendToDestination(Document samlDocument, String relayState, String destination,
                                     HttpServletResponse response, boolean request) throws IOException, SAXException, GeneralSecurityException {
    	if (!ignoreSignatures) {
            SAML2Signature samlSignature = new SAML2Signature();

            Node nextSibling = samlSignature.getNextSiblingOfIssuer(samlDocument);
            if (nextSibling != null) {
                samlSignature.setNextSibling(nextSibling);
            }
            KeyPair keypair = keyManager.getSigningKeyPair();
            samlSignature.signSAMLDocument(samlDocument, keypair);
        }
        String samlMessage = PostBindingUtil.base64Encode(DocumentUtil.getDocumentAsString(samlDocument));
        PostBindingUtil.sendPost(new DestinationInfoHolder(destination, samlMessage, relayState), response, request);
    }
    
    protected boolean validate(HttpServletRequest request) throws IOException, GeneralSecurityException {
        return request.getParameter("SAMLResponse") != null;
    }

    protected boolean verifySignature(SAMLDocumentHolder samlDocumentHolder) throws IssuerNotTrustedException {
        Document samlResponse = samlDocumentHolder.getSamlDocument();
        SAML2Object samlObject = samlDocumentHolder.getSamlObject();

        String issuerID = null;
        if (samlObject instanceof StatusResponseType) {
            issuerID = ((StatusResponseType) samlObject).getIssuer().getValue();
        } else {
            issuerID = ((RequestAbstractType) samlObject).getIssuer().getValue();
        }

        if (issuerID == null)
            throw new IssuerNotTrustedException(ErrorCodes.NULL_VALUE + "IssuerID missing");

        URL issuerURL;
        try {
            issuerURL = new URL(issuerID);
        } catch (MalformedURLException e1) {
            throw new IssuerNotTrustedException(e1);
        }

        try {
            PublicKey publicKey = keyManager.getValidatingKey(issuerURL.getHost());
            log.trace("Going to verify signature in the saml response from IDP");
            boolean sigResult = XMLSignatureUtil.validate(samlResponse, publicKey);
            log.trace("Signature verification=" + sigResult);
            return sigResult;
        } catch (TrustKeyConfigurationException e) {
            log.error("Unable to verify signature", e);
        } catch (TrustKeyProcessingException e) {
            log.error("Unable to verify signature", e);
        } catch (MarshalException e) {
            log.error("Unable to verify signature", e);
        } catch (XMLSignatureException e) {
            log.error("Unable to verify signature", e);
        }
        return false;
    }

    protected void isTrusted(String issuer) throws IssuerNotTrustedException {
        try {
            URL url = new URL(issuer);
            String issuerDomain = url.getHost();
            TrustType idpTrust = spConfiguration.getTrust();
            if (idpTrust != null) {
                String domainsTrusted = idpTrust.getDomains();
                if (domainsTrusted.indexOf(issuerDomain) < 0)
                    throw new IssuerNotTrustedException(issuer);
            }
        } catch (Exception e) {
            throw new IssuerNotTrustedException(e.getLocalizedMessage(), e);
        }
    }

    protected ResponseType decryptAssertion(ResponseType responseType) {
        throw new RuntimeException(ErrorCodes.PROCESSING_EXCEPTION + "This filter does not handle encryption");
    }

    /**
     * Handle the SAMLResponse from the IDP
     *
     * @param request entire request from IDP
     * @param responseType ResponseType that has been generated
     * @param serverEnvironment tomcat,jboss etc
     *
     * @return
     *
     * @throws AssertionExpiredException
     */
    public Principal handleSAMLResponse(HttpServletRequest request, ResponseType responseType) throws ConfigurationException,
            AssertionExpiredException {
    	if (request == null)
            throw new IllegalArgumentException(ErrorCodes.NULL_ARGUMENT + "request");
        if (responseType == null)
            throw new IllegalArgumentException(ErrorCodes.NULL_ARGUMENT + "response type");

        StatusType statusType = responseType.getStatus();
        if (statusType == null)
            throw new IllegalArgumentException(ErrorCodes.NULL_VALUE + "Status Type from the IDP");

        String statusValue = statusType.getStatusCode().getValue().toASCIIString();
        if (JBossSAMLURIConstants.STATUS_SUCCESS.get().equals(statusValue) == false)
            throw new SecurityException(ErrorCodes.IDP_AUTH_FAILED + "IDP forbid the user");

        List<org.picketlink.identity.federation.saml.v2.protocol.ResponseType.RTChoiceType> assertions = responseType
                .getAssertions();
        if (assertions.size() == 0)
            throw new IllegalStateException(ErrorCodes.NULL_VALUE + "No assertions in reply from IDP");

        AssertionType assertion = assertions.get(0).getAssertion();
        // Check for validity of assertion
        boolean expiredAssertion = AssertionUtil.hasExpired(assertion);
        if (expiredAssertion)
            throw new AssertionExpiredException(ErrorCodes.EXPIRED_ASSERTION);

        SubjectType subject = assertion.getSubject();
        /*
         * JAXBElement<NameIDType> jnameID = (JAXBElement<NameIDType>) subject.getContent().get(0); NameIDType nameID =
         * jnameID.getValue();
         */
        NameIDType nameID = (NameIDType) subject.getSubType().getBaseID();

        final String userName = nameID.getValue();
        List<String> roles = new ArrayList<String>();

        // Let us get the roles
        AttributeStatementType attributeStatement = (AttributeStatementType) assertion.getStatements().iterator().next();
        List<ASTChoiceType> attList = attributeStatement.getAttributes();
        for (ASTChoiceType obj : attList) {
            AttributeType attr = obj.getAttribute();
            String roleName = (String) attr.getAttributeValue().get(0);
            roles.add(roleName);
        }
        
        Principal principal = new Principal() {
            public String getName() {
                return userName;
            }
        };

        // Validate the roles
        boolean validRole = roleValidator.userInRole(principal, roles);
        if (!validRole) {
            if (trace)
                log.trace("Invalid role:" + roles);
            principal = null;
        }
        return principal;
    }
    
    protected void sendError403(HttpServletResponse response) throws IOException {
    	SAML2HandlerResponse saml2HandlerResponse = new DefaultSAML2HandlerResponse();
		saml2HandlerResponse.setError(403, "User Principal not determined: Forbidden");
		response.sendError(saml2HandlerResponse.getErrorCode());
    }

    protected boolean checkUrlsExcluded(List<String> excludedURLs, String url) {
    	boolean isExcludedURL = false;
        if(excludedURLs != null) {
	         for (String s : excludedURLs) {
	             if (url.indexOf(s) > -1) {
	                 isExcludedURL = true;
	                 break;
	             }
	         }
        }
        
        return isExcludedURL;
    }

    private boolean validateExtension(String url) {
    	if (url.endsWith(".jpg") || url.endsWith(".png") || url.endsWith(".gif")
    			|| url.endsWith(".bmp") || url.endsWith(".js") || url.endsWith(".css")) {
    		return true;
    	}
  	  	return false;
    }
    
    private boolean validateAdminUrl(HttpSession session, String url) {
    	String adminUrl = (String) session.getAttribute("adminUrl");
    	if (adminUrl != null && adminUrl.endsWith(url)) {
    		return true;
        }
    	
    	return false;
    }
    
    /*private String getUrlApplication(String url, int length) {
    	return url.substring(0, url.length() - length);
    }

    private void resetTimeout() {
    	if (!start) {
	    	this.start = true;
	    	this.startTime = 0;
    	}
    }*/
    
}
