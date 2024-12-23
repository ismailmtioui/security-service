package dcc.tp2.security_microservice.service;

public class UserDTO {
    private String email;
    private String password;
    private String cin;
    private String role; // Add this field

    // Constructors
    public UserDTO(String email, String password, String cin, String role) {
        this.email = email;
        this.password = password;
        this.cin = cin;
        this.role = role;
    }

    // Getters and Setters
    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public String getCin() {
        return cin;
    }

    public void setCin(String cin) {
        this.cin = cin;
    }

    public String getRole() {
        return role;
    }

    public void setRole(String role) {
        this.role = role;
    }
}
