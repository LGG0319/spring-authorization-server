/*
 * Copyright 2020-2024 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers;

import java.net.URI;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import com.nimbusds.jose.jwk.source.JWKSource;

import org.springframework.context.ApplicationListener;
import org.springframework.context.event.GenericApplicationListenerAdapter;
import org.springframework.context.event.SmartApplicationListener;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.annotation.web.configurers.ExceptionHandlingConfigurer;
import org.springframework.security.context.DelegatingApplicationListener;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.session.SessionRegistry;
import org.springframework.security.core.session.SessionRegistryImpl;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.OAuth2Token;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationException;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenGenerator;
import org.springframework.security.oauth2.server.authorization.web.NimbusJwkSetEndpointFilter;
import org.springframework.security.web.authentication.HttpStatusEntryPoint;
import org.springframework.security.web.authentication.preauth.AbstractPreAuthenticatedProcessingFilter;
import org.springframework.security.web.context.SecurityContextHolderFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.OrRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.Assert;

/**
 * An {@link AbstractHttpConfigurer} for OAuth 2.0 Authorization Server support.
 *
 * @author Joe Grandja
 * @author Daniel Garnier-Moiroux
 * @author Gerardo Roza
 * @author Ovidiu Popa
 * @author Gaurav Tiwari
 * @since 0.0.1
 * @see AbstractHttpConfigurer
 * @see OAuth2ClientAuthenticationConfigurer
 * @see OAuth2AuthorizationServerMetadataEndpointConfigurer
 * @see OAuth2AuthorizationEndpointConfigurer
 * @see OAuth2TokenEndpointConfigurer
 * @see OAuth2TokenIntrospectionEndpointConfigurer
 * @see OAuth2TokenRevocationEndpointConfigurer
 * @see OAuth2DeviceAuthorizationEndpointConfigurer
 * @see OAuth2DeviceVerificationEndpointConfigurer
 * @see OidcConfigurer
 * @see RegisteredClientRepository
 * @see OAuth2AuthorizationService
 * @see OAuth2AuthorizationConsentService
 * @see NimbusJwkSetEndpointFilter
 * OAuth2 授权服务器配置器
 */
public final class OAuth2AuthorizationServerConfigurer
		extends AbstractHttpConfigurer<OAuth2AuthorizationServerConfigurer, HttpSecurity> {

	// 所有授权服务器端点配置器
	private final Map<Class<? extends AbstractOAuth2Configurer>, AbstractOAuth2Configurer> configurers = createConfigurers();
	// 匹配所有授权服务器端点对应的请求，以及JwkSet端点请求
	private RequestMatcher endpointsMatcher;

	/**
	 * Sets the repository of registered clients.
	 * @param registeredClientRepository the repository of registered clients
	 * @return the {@link OAuth2AuthorizationServerConfigurer} for further configuration
	 */
	public OAuth2AuthorizationServerConfigurer registeredClientRepository(
			RegisteredClientRepository registeredClientRepository) {
		Assert.notNull(registeredClientRepository, "registeredClientRepository cannot be null");
		getBuilder().setSharedObject(RegisteredClientRepository.class, registeredClientRepository);
		return this;
	}

	/**
	 * Sets the authorization service.
	 * @param authorizationService the authorization service
	 * @return the {@link OAuth2AuthorizationServerConfigurer} for further configuration
	 */
	public OAuth2AuthorizationServerConfigurer authorizationService(OAuth2AuthorizationService authorizationService) {
		Assert.notNull(authorizationService, "authorizationService cannot be null");
		getBuilder().setSharedObject(OAuth2AuthorizationService.class, authorizationService);
		return this;
	}

	/**
	 * Sets the authorization consent service.
	 * @param authorizationConsentService the authorization consent service
	 * @return the {@link OAuth2AuthorizationServerConfigurer} for further configuration
	 */
	public OAuth2AuthorizationServerConfigurer authorizationConsentService(
			OAuth2AuthorizationConsentService authorizationConsentService) {
		Assert.notNull(authorizationConsentService, "authorizationConsentService cannot be null");
		getBuilder().setSharedObject(OAuth2AuthorizationConsentService.class, authorizationConsentService);
		return this;
	}

	/**
	 * Sets the authorization server settings.
	 * @param authorizationServerSettings the authorization server settings
	 * @return the {@link OAuth2AuthorizationServerConfigurer} for further configuration
	 */
	public OAuth2AuthorizationServerConfigurer authorizationServerSettings(
			AuthorizationServerSettings authorizationServerSettings) {
		Assert.notNull(authorizationServerSettings, "authorizationServerSettings cannot be null");
		getBuilder().setSharedObject(AuthorizationServerSettings.class, authorizationServerSettings);
		return this;
	}

	/**
	 * Sets the token generator.
	 * @param tokenGenerator the token generator
	 * @return the {@link OAuth2AuthorizationServerConfigurer} for further configuration
	 * @since 0.2.3
	 */
	public OAuth2AuthorizationServerConfigurer tokenGenerator(
			OAuth2TokenGenerator<? extends OAuth2Token> tokenGenerator) {
		Assert.notNull(tokenGenerator, "tokenGenerator cannot be null");
		getBuilder().setSharedObject(OAuth2TokenGenerator.class, tokenGenerator);
		return this;
	}

	/**
	 * Configures OAuth 2.0 Client Authentication.
	 * @param clientAuthenticationCustomizer the {@link Customizer} providing access to
	 * the {@link OAuth2ClientAuthenticationConfigurer}
	 * @return the {@link OAuth2AuthorizationServerConfigurer} for further configuration
	 */
	public OAuth2AuthorizationServerConfigurer clientAuthentication(
			Customizer<OAuth2ClientAuthenticationConfigurer> clientAuthenticationCustomizer) {
		clientAuthenticationCustomizer.customize(getConfigurer(OAuth2ClientAuthenticationConfigurer.class));
		return this;
	}

	/**
	 * Configures the OAuth 2.0 Authorization Server Metadata Endpoint.
	 * @param authorizationServerMetadataEndpointCustomizer the {@link Customizer}
	 * providing access to the {@link OAuth2AuthorizationServerMetadataEndpointConfigurer}
	 * @return the {@link OAuth2AuthorizationServerConfigurer} for further configuration
	 * @since 0.4.0
	 */
	public OAuth2AuthorizationServerConfigurer authorizationServerMetadataEndpoint(
			Customizer<OAuth2AuthorizationServerMetadataEndpointConfigurer> authorizationServerMetadataEndpointCustomizer) {
		authorizationServerMetadataEndpointCustomizer
			.customize(getConfigurer(OAuth2AuthorizationServerMetadataEndpointConfigurer.class));
		return this;
	}

	/**
	 * Configures the OAuth 2.0 Authorization Endpoint.
	 * @param authorizationEndpointCustomizer the {@link Customizer} providing access to
	 * the {@link OAuth2AuthorizationEndpointConfigurer}
	 * @return the {@link OAuth2AuthorizationServerConfigurer} for further configuration
	 */
	public OAuth2AuthorizationServerConfigurer authorizationEndpoint(
			Customizer<OAuth2AuthorizationEndpointConfigurer> authorizationEndpointCustomizer) {
		authorizationEndpointCustomizer.customize(getConfigurer(OAuth2AuthorizationEndpointConfigurer.class));
		return this;
	}

	/**
	 * Configures the OAuth 2.0 Token Endpoint.
	 * @param tokenEndpointCustomizer the {@link Customizer} providing access to the
	 * {@link OAuth2TokenEndpointConfigurer}
	 * @return the {@link OAuth2AuthorizationServerConfigurer} for further configuration
	 */
	public OAuth2AuthorizationServerConfigurer tokenEndpoint(
			Customizer<OAuth2TokenEndpointConfigurer> tokenEndpointCustomizer) {
		tokenEndpointCustomizer.customize(getConfigurer(OAuth2TokenEndpointConfigurer.class));
		return this;
	}

	/**
	 * Configures the OAuth 2.0 Token Introspection Endpoint.
	 * @param tokenIntrospectionEndpointCustomizer the {@link Customizer} providing access
	 * to the {@link OAuth2TokenIntrospectionEndpointConfigurer}
	 * @return the {@link OAuth2AuthorizationServerConfigurer} for further configuration
	 * @since 0.2.3
	 */
	public OAuth2AuthorizationServerConfigurer tokenIntrospectionEndpoint(
			Customizer<OAuth2TokenIntrospectionEndpointConfigurer> tokenIntrospectionEndpointCustomizer) {
		tokenIntrospectionEndpointCustomizer.customize(getConfigurer(OAuth2TokenIntrospectionEndpointConfigurer.class));
		return this;
	}

	/**
	 * Configures the OAuth 2.0 Token Revocation Endpoint.
	 * @param tokenRevocationEndpointCustomizer the {@link Customizer} providing access to
	 * the {@link OAuth2TokenRevocationEndpointConfigurer}
	 * @return the {@link OAuth2AuthorizationServerConfigurer} for further configuration
	 * @since 0.2.2
	 */
	public OAuth2AuthorizationServerConfigurer tokenRevocationEndpoint(
			Customizer<OAuth2TokenRevocationEndpointConfigurer> tokenRevocationEndpointCustomizer) {
		tokenRevocationEndpointCustomizer.customize(getConfigurer(OAuth2TokenRevocationEndpointConfigurer.class));
		return this;
	}

	/**
	 * Configures the OAuth 2.0 Device Authorization Endpoint.
	 * @param deviceAuthorizationEndpointCustomizer the {@link Customizer} providing
	 * access to the {@link OAuth2DeviceAuthorizationEndpointConfigurer}
	 * @return the {@link OAuth2AuthorizationServerConfigurer} for further configuration
	 * @since 1.1
	 */
	public OAuth2AuthorizationServerConfigurer deviceAuthorizationEndpoint(
			Customizer<OAuth2DeviceAuthorizationEndpointConfigurer> deviceAuthorizationEndpointCustomizer) {
		deviceAuthorizationEndpointCustomizer
			.customize(getConfigurer(OAuth2DeviceAuthorizationEndpointConfigurer.class));
		return this;
	}

	/**
	 * Configures the OAuth 2.0 Device Verification Endpoint.
	 * @param deviceVerificationEndpointCustomizer the {@link Customizer} providing access
	 * to the {@link OAuth2DeviceVerificationEndpointConfigurer}
	 * @return the {@link OAuth2AuthorizationServerConfigurer} for further configuration
	 * @since 1.1
	 */
	public OAuth2AuthorizationServerConfigurer deviceVerificationEndpoint(
			Customizer<OAuth2DeviceVerificationEndpointConfigurer> deviceVerificationEndpointCustomizer) {
		deviceVerificationEndpointCustomizer.customize(getConfigurer(OAuth2DeviceVerificationEndpointConfigurer.class));
		return this;
	}

	/**
	 * Configures OpenID Connect 1.0 support (disabled by default).
	 * @param oidcCustomizer the {@link Customizer} providing access to the
	 * {@link OidcConfigurer}
	 * @return the {@link OAuth2AuthorizationServerConfigurer} for further configuration
	 * 启用OpenID Connect 1.0支持（默认关闭）
	 */
	public OAuth2AuthorizationServerConfigurer oidc(Customizer<OidcConfigurer> oidcCustomizer) {
		OidcConfigurer oidcConfigurer = getConfigurer(OidcConfigurer.class);
		if (oidcConfigurer == null) {
			addConfigurer(OidcConfigurer.class, new OidcConfigurer(this::postProcess));
			oidcConfigurer = getConfigurer(OidcConfigurer.class);
		}
		oidcCustomizer.customize(oidcConfigurer);
		return this;
	}

	/**
	 * Returns a {@link RequestMatcher} for the authorization server endpoints.
	 * @return a {@link RequestMatcher} for the authorization server endpoints
	 */
	public RequestMatcher getEndpointsMatcher() {
		// Return a deferred RequestMatcher
		// since endpointsMatcher is constructed in init(HttpSecurity).
		return (request) -> this.endpointsMatcher.matches(request);
	}

	// 配置器初始化
	@Override
	public void init(HttpSecurity httpSecurity) {
		// 获取授权服务器设置(各端点url)
		AuthorizationServerSettings authorizationServerSettings = OAuth2ConfigurerUtils
			.getAuthorizationServerSettings(httpSecurity);
		// 校验issuerUri
		validateAuthorizationServerSettings(authorizationServerSettings);
		// 处理OpenID Connect认证请求
		if (isOidcEnabled()) {
			// Add OpenID Connect session tracking capabilities.
			// 如果启用OpenID Connect 1.0
			// 添加 OpenID Connect 会话跟踪能力
			initSessionRegistry(httpSecurity);
			SessionRegistry sessionRegistry = httpSecurity.getSharedObject(SessionRegistry.class);
			// 授权端点设置会话认证策略
			OAuth2AuthorizationEndpointConfigurer authorizationEndpointConfigurer = getConfigurer(
					OAuth2AuthorizationEndpointConfigurer.class);
			authorizationEndpointConfigurer.setSessionAuthenticationStrategy((authentication, request, response) -> {
				// 如果认证请求是使用授权码模式的OAuth2认证请求，且scope包含openid，则将会话注册到会话注册表
				if (authentication instanceof OAuth2AuthorizationCodeRequestAuthenticationToken authorizationCodeRequestAuthentication) {
					if (authorizationCodeRequestAuthentication.getScopes().contains(OidcScopes.OPENID)) {
						if (sessionRegistry.getSessionInformation(request.getSession().getId()) == null) {
							sessionRegistry.registerNewSession(request.getSession().getId(),
									((Authentication) authorizationCodeRequestAuthentication.getPrincipal())
										.getPrincipal());
						}
					}
				}
			});
		}
		// 如果OpenID Connect 没有启用.
		// 添加认证校验器，拒绝scope包含openid的认证请求
		else {
			// OpenID Connect is disabled.
			// Add an authentication validator that rejects authentication requests.
			OAuth2AuthorizationEndpointConfigurer authorizationEndpointConfigurer = getConfigurer(
					OAuth2AuthorizationEndpointConfigurer.class);
			authorizationEndpointConfigurer
				.addAuthorizationCodeRequestAuthenticationValidator((authenticationContext) -> {
					OAuth2AuthorizationCodeRequestAuthenticationToken authorizationCodeRequestAuthentication = authenticationContext
						.getAuthentication();
					if (authorizationCodeRequestAuthentication.getScopes().contains(OidcScopes.OPENID)) {
						OAuth2Error error = new OAuth2Error(OAuth2ErrorCodes.INVALID_SCOPE,
								"OpenID Connect 1.0 authentication requests are restricted.",
								"https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.2.1");
						throw new OAuth2AuthorizationCodeRequestAuthenticationException(error,
								authorizationCodeRequestAuthentication);
					}
				});
		}
		// 构造授权端点请求匹配器
		List<RequestMatcher> requestMatchers = new ArrayList<>();
		// 添加每个端点对应的匹配规则
		this.configurers.values().forEach((configurer) -> {
			configurer.init(httpSecurity);
			requestMatchers.add(configurer.getRequestMatcher());
		});
		String jwkSetEndpointUri = authorizationServerSettings.isMultipleIssuersAllowed()
				? OAuth2ConfigurerUtils.withMultipleIssuersPattern(authorizationServerSettings.getJwkSetEndpoint())
				: authorizationServerSettings.getJwkSetEndpoint();
		// 添加JwkSet端点请求匹配规则
		requestMatchers.add(new AntPathRequestMatcher(jwkSetEndpointUri, HttpMethod.GET.name()));
		this.endpointsMatcher = new OrRequestMatcher(requestMatchers);
		// 当令牌获取/内省/撤回/设备认证端点发生访问拒绝异常或者认证异常时返回401未授权响应
		ExceptionHandlingConfigurer<HttpSecurity> exceptionHandling = httpSecurity
			.getConfigurer(ExceptionHandlingConfigurer.class);
		if (exceptionHandling != null) {
			exceptionHandling.defaultAuthenticationEntryPointFor(new HttpStatusEntryPoint(HttpStatus.UNAUTHORIZED),
					new OrRequestMatcher(getRequestMatcher(OAuth2TokenEndpointConfigurer.class),
							getRequestMatcher(OAuth2TokenIntrospectionEndpointConfigurer.class),
							getRequestMatcher(OAuth2TokenRevocationEndpointConfigurer.class),
							getRequestMatcher(OAuth2DeviceAuthorizationEndpointConfigurer.class)));
		}
	}

	// 执行安全配置
	@Override
	public void configure(HttpSecurity httpSecurity) {
		// 应用各端点配置器
		this.configurers.values().forEach((configurer) -> configurer.configure(httpSecurity));

		AuthorizationServerSettings authorizationServerSettings = OAuth2ConfigurerUtils
			.getAuthorizationServerSettings(httpSecurity);
		// 获取授权服务器设置
		AuthorizationServerContextFilter authorizationServerContextFilter = new AuthorizationServerContextFilter(
				authorizationServerSettings);
		httpSecurity.addFilterAfter(postProcess(authorizationServerContextFilter), SecurityContextHolderFilter.class);
		// 添加JwkSet端点过滤器
		JWKSource<com.nimbusds.jose.proc.SecurityContext> jwkSource = OAuth2ConfigurerUtils.getJwkSource(httpSecurity);
		if (jwkSource != null) {
			String jwkSetEndpointUri = authorizationServerSettings.isMultipleIssuersAllowed()
					? OAuth2ConfigurerUtils.withMultipleIssuersPattern(authorizationServerSettings.getJwkSetEndpoint())
					: authorizationServerSettings.getJwkSetEndpoint();
			NimbusJwkSetEndpointFilter jwkSetEndpointFilter = new NimbusJwkSetEndpointFilter(jwkSource,
					jwkSetEndpointUri);
			httpSecurity.addFilterBefore(postProcess(jwkSetEndpointFilter),
					AbstractPreAuthenticatedProcessingFilter.class);
		}
	}

	private boolean isOidcEnabled() {
		return getConfigurer(OidcConfigurer.class) != null;
	}
	// 创建OAuth2服务器端点配置器
	private Map<Class<? extends AbstractOAuth2Configurer>, AbstractOAuth2Configurer> createConfigurers() {
		Map<Class<? extends AbstractOAuth2Configurer>, AbstractOAuth2Configurer> configurers = new LinkedHashMap<>();
		// 客户端认证
		configurers.put(OAuth2ClientAuthenticationConfigurer.class,
				new OAuth2ClientAuthenticationConfigurer(this::postProcess));
		// 授权服务器元数据端点
		configurers.put(OAuth2AuthorizationServerMetadataEndpointConfigurer.class,
				new OAuth2AuthorizationServerMetadataEndpointConfigurer(this::postProcess));
		// 授权端点
		configurers.put(OAuth2AuthorizationEndpointConfigurer.class,
				new OAuth2AuthorizationEndpointConfigurer(this::postProcess));
		// 令牌获取端点
		configurers.put(OAuth2TokenEndpointConfigurer.class, new OAuth2TokenEndpointConfigurer(this::postProcess));
		// 令牌内省端点
		configurers.put(OAuth2TokenIntrospectionEndpointConfigurer.class,
				new OAuth2TokenIntrospectionEndpointConfigurer(this::postProcess));
		// 令牌撤回端点
		configurers.put(OAuth2TokenRevocationEndpointConfigurer.class,
				new OAuth2TokenRevocationEndpointConfigurer(this::postProcess));
		// 设备授权端点
		configurers.put(OAuth2DeviceAuthorizationEndpointConfigurer.class,
				new OAuth2DeviceAuthorizationEndpointConfigurer(this::postProcess));
		// 设备校验端点
		configurers.put(OAuth2DeviceVerificationEndpointConfigurer.class,
				new OAuth2DeviceVerificationEndpointConfigurer(this::postProcess));
		return configurers;
	}

	@SuppressWarnings("unchecked")
	private <T> T getConfigurer(Class<T> type) {
		return (T) this.configurers.get(type);
	}

	private <T extends AbstractOAuth2Configurer> void addConfigurer(Class<T> configurerType, T configurer) {
		this.configurers.put(configurerType, configurer);
	}

	private <T extends AbstractOAuth2Configurer> RequestMatcher getRequestMatcher(Class<T> configurerType) {
		T configurer = getConfigurer(configurerType);
		return (configurer != null) ? configurer.getRequestMatcher() : null;
	}

	private static void validateAuthorizationServerSettings(AuthorizationServerSettings authorizationServerSettings) {
		if (authorizationServerSettings.getIssuer() != null) {
			URI issuerUri;
			try {
				issuerUri = new URI(authorizationServerSettings.getIssuer());
				issuerUri.toURL();
			}
			catch (Exception ex) {
				throw new IllegalArgumentException("issuer must be a valid URL", ex);
			}
			// rfc8414 https://datatracker.ietf.org/doc/html/rfc8414#section-2
			if (issuerUri.getQuery() != null || issuerUri.getFragment() != null) {
				throw new IllegalArgumentException("issuer cannot contain query or fragment component");
			}
		}
	}

	private static void initSessionRegistry(HttpSecurity httpSecurity) {
		SessionRegistry sessionRegistry = OAuth2ConfigurerUtils.getOptionalBean(httpSecurity, SessionRegistry.class);
		if (sessionRegistry == null) {
			sessionRegistry = new SessionRegistryImpl();
			registerDelegateApplicationListener(httpSecurity, (SessionRegistryImpl) sessionRegistry);
		}
		httpSecurity.setSharedObject(SessionRegistry.class, sessionRegistry);
	}

	private static void registerDelegateApplicationListener(HttpSecurity httpSecurity,
			ApplicationListener<?> delegate) {
		DelegatingApplicationListener delegatingApplicationListener = OAuth2ConfigurerUtils
			.getOptionalBean(httpSecurity, DelegatingApplicationListener.class);
		if (delegatingApplicationListener == null) {
			return;
		}
		SmartApplicationListener smartListener = new GenericApplicationListenerAdapter(delegate);
		delegatingApplicationListener.addListener(smartListener);
	}

}
