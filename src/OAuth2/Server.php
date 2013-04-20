<?php

/**
* Service class for OAuth
* This class serves only to wrap the other Controller classes
* @see OAuth2_Controller_ResourceController
* @see OAuth2_Controller_AuthorizeController
* @see OAuth2_Controller_TokenController
*/
class OAuth2_Server implements OAuth2_Controller_ResourceControllerInterface,
    OAuth2_Controller_AuthorizeControllerInterface, OAuth2_Controller_TokenControllerInterface
{
    // factory (for B.C.)
    protected $serverFactory;

    // controllers
    protected $resourceController;
    protected $authorizeController;
    protected $tokenController;

    /**
     * This constructor is a mess for backwards compatibility
     *
     * @see OAuth2_ServerFactory
     */
    public function __construct($storage = array(), array $config = array(), array $grantTypes = array(), array $responseTypes = array(), OAuth2_ResponseType_AccessTokenInterface $accessTokenResponseType = null, OAuth2_ScopeInterface $scopeUtil = null)
    {
        $this->serverFactory = new OAuth2_ServerFactory($storage, $config, $grantTypes, $responseTypes, $accessTokenResponseType, $scopeUtil);
    }

    public function getAuthorizeController()
    {
        if (is_null($this->authorizeController)) {
            $this->authorizeController = $this->serverFactory->getAuthorizeController();
        }
        return $this->authorizeController;
    }

    public function setAuthorizeController(OAuth2_Controller_AuthorizeControllerInterface $authorizeController)
    {
        $this->authorizeController = $authorizeController;
    }

    public function getTokenController()
    {
        if (is_null($this->tokenController)) {
            $this->tokenController = $this->serverFactory->getTokenController();
        }
        return $this->tokenController;
    }

    public function setTokenController(OAuth2_Controller_TokenControllerInterface $tokenController)
    {
        $this->tokenController = $tokenController;
    }

    public function getResourceController()
    {
        if (is_null($this->resourceController)) {
            $this->resourceController = $this->serverFactory->getResourceController();
        }
        return $this->resourceController;
    }

    public function setResourceController(OAuth2_Controller_ResourceControllerInterface $resourceController)
    {
        $this->resourceController = $resourceController;
    }

    /**
     * Grant or deny a requested access token.
     * This would be called from the "/token" endpoint as defined in the spec.
     * Obviously, you can call your endpoint whatever you want.
     *
     * @param $request - OAuth2_Request
     * Request object to grant access token
     *
     * @return
     * OAuth_Response
     *
     * @throws InvalidArgumentException
     * @throws LogicException
     *
     * @see http://tools.ietf.org/html/rfc6749#section-4
     * @see http://tools.ietf.org/html/rfc6749#section-10.6
     * @see http://tools.ietf.org/html/rfc6749#section-4.1.3
     *
     * @ingroup oauth2_section_4
     */
    public function handleTokenRequest(OAuth2_RequestInterface $request)
    {
        $value = $this->getTokenController()->handleTokenRequest($request);
        $this->response = $this->tokenController->getResponse();
        return $value;
    }

    public function grantAccessToken(OAuth2_RequestInterface $request)
    {
        $value = $this->getTokenController()->grantAccessToken($request);
        $this->response = $this->tokenController->getResponse();
        return $value;
    }

    public function getClientCredentials(OAuth2_RequestInterface $request)
    {
        $value = $this->getTokenController()->getClientCredentials($request);
        $this->response = $this->tokenController->getResponse();
        return $value;
    }

    /**
     * Redirect the user appropriately after approval.
     *
     * After the user has approved or denied the resource request the
     * authorization server should call this function to redirect the user
     * appropriately.
     *
     * @param $request
     * The request should have the follow parameters set in the querystring:
     * - response_type: The requested response: an access token, an
     * authorization code, or both.
     * - client_id: The client identifier as described in Section 2.
     * - redirect_uri: An absolute URI to which the authorization server
     * will redirect the user-agent to when the end-user authorization
     * step is completed.
     * - scope: (optional) The scope of the resource request expressed as a
     * list of space-delimited strings.
     * - state: (optional) An opaque value used by the client to maintain
     * state between the request and callback.
     *
     * @param $is_authorized
     * TRUE or FALSE depending on whether the user authorized the access.
     *
     * @param $user_id
     * Identifier of user who authorized the client
     *
     * @see http://tools.ietf.org/html/rfc6749#section-4
     *
     * @ingroup oauth2_section_4
     */
    public function handleAuthorizeRequest(OAuth2_RequestInterface $request, $is_authorized, $user_id = null)
    {
        $value = $this->getAuthorizeController()->handleAuthorizeRequest($request, $is_authorized, $user_id);
        $this->response = $this->authorizeController->getResponse();
        return $value;
    }

    /**
     * Pull the authorization request data out of the HTTP request.
     * - The redirect_uri is OPTIONAL as per draft 20. But your implementation can enforce it
     * by setting $config['enforce_redirect'] to true.
     * - The state is OPTIONAL but recommended to enforce CSRF. Draft 21 states, however, that
     * CSRF protection is MANDATORY. You can enforce this by setting the $config['enforce_state'] to true.
     *
     * The draft specifies that the parameters should be retrieved from GET, override the Response
     * object to change this
     *
     * @return
     * The authorization parameters so the authorization server can prompt
     * the user for approval if valid.
     *
     * @see http://tools.ietf.org/html/rfc6749#section-4.1.1
     * @see http://tools.ietf.org/html/rfc6749#section-10.12
     *
     * @ingroup oauth2_section_3
     */
    public function validateAuthorizeRequest(OAuth2_RequestInterface $request)
    {
        $value = $this->getAuthorizeController()->validateAuthorizeRequest($request);
        $this->response = $this->authorizeController->getResponse();
        return $value;
    }

    public function verifyResourceRequest(OAuth2_RequestInterface $request, $scope = null)
    {
        $value = $this->getResourceController()->verifyResourceRequest($request, $scope);
        $this->response = $this->resourceController->getResponse();
        return $value;
    }

    public function getAccessTokenData(OAuth2_RequestInterface $request, $scope = null)
    {
        $value = $this->getResourceController()->getAccessTokenData($request, $scope);
        $this->response = $this->resourceController->getResponse();
        return $value;
    }

    public function addGrantType(OAuth2_GrantTypeInterface $grantType, $key = null)
    {
        $this->serverFactory->addGrantType($grantType, $key);
    }

    public function addStorage($storage, $key = null)
    {
        $this->serverFactory->addStorage($storage, $key);
    }

    public function addResponseType(OAuth2_ResponseTypeInterface $responseType, $key = null)
    {
        $this->serverFactory->addResponseType($responseType, $key);
    }

    public function setScopeUtil($scopeUtil)
    {
        $this->serverFactory->setScopeUtil($scopeUtil);
    }

    public function getResponse()
    {
        return $this->response;
    }
}
