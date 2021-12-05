package com.example.jwt.demo.repositories;

import com.example.jwt.demo.models.RefreshToken;
import com.example.jwt.demo.models.User;
import java.util.Optional;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface RefreshTokenRepository extends JpaRepository<RefreshToken, Long> {

    @Override
    Optional<RefreshToken> findById(Long id);

    Optional<RefreshToken> findByToken(String token);
    
    int deleteByUser(User user);
}
