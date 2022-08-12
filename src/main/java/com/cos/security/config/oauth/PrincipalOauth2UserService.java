package com.cos.security.config.oauth;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

import com.cos.security.config.auth.PrincipalDetails;
import com.cos.security.model.SecurityUser;
import com.cos.security.repository.SecurityUserRepository;

@Service
public class PrincipalOauth2UserService extends DefaultOAuth2UserService{

	@Autowired
	private BCryptPasswordEncoder bCryptPasswordEncoder;
	
	@Autowired
	private SecurityUserRepository userRepository;
	
	@Override
	public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
		
		OAuth2User oauth2User = super.loadUser(userRequest);
		String provider =  userRequest.getClientRegistration().getClientId();
		String providerId = oauth2User.getAttribute("sub");
		String username = provider + "_" + provider;
		String password = bCryptPasswordEncoder.encode("GOOGLE");
		String email = oauth2User.getAttribute("email");
		String role = "ROLE_USER";
		
		SecurityUser userEntity = userRepository.findByUsername(username);
		
		if (userEntity == null) {
			
			userEntity = SecurityUser.builder()
					.username(username)
					.password(password)
					.email(email)
					.role(role)
					.provider(provider)
					.providerId(providerId)
					.build();
			userRepository.save(userEntity);
		} 
		
		return new PrincipalDetails(userEntity, oauth2User.getAttributes());
	}
}
