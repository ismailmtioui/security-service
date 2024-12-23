package dcc.tp2.security_microservice.service;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

import java.util.ArrayList;
import java.util.Collection;

@Service
public class UserDetailService implements UserDetailsService {

    private final RestTemplate restTemplate;

    public UserDetailService() {
        this.restTemplate = new RestTemplate();
    }

    @Override
    public UserDetails loadUserByUsername(String combinedUsername) throws UsernameNotFoundException {
        String[] parts = combinedUsername.split(":");
        if (parts.length != 2) {
            throw new UsernameNotFoundException("Invalid username format. Expected format: email:type");
        }

        String email = parts[0];
        String userType = parts[1];

        // Call usermanagement_service to retrieve user info
        String userUrl = "http://localhost:8083/users/email/" + email;
        UserDTO userDTO = restTemplate.getForObject(userUrl, UserDTO.class);

        if (userDTO == null) {
            throw new UsernameNotFoundException("User not found with email: " + email);
        }

        // Map role to authority
        Collection<GrantedAuthority> authorities = new ArrayList<>();
        authorities.add(new SimpleGrantedAuthority(userDTO.getRole()));

        return new User(userDTO.getEmail(), "{noop}" + userDTO.getPassword(), authorities);
    }
}
