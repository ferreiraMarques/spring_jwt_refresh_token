package com.example.jwt.demo.repositories;

import com.example.jwt.demo.models.User;
import java.util.Optional;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface UserRepository extends JpaRepository<User, Long> {
    
    Optional<User> findByUserName(String username);
    
    Boolean existsByUserName(String username);
    
    Boolean existsByEmail(String email);
}
