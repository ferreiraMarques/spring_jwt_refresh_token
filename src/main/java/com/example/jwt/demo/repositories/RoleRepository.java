package com.example.jwt.demo.repositories;

import com.example.jwt.demo.models.ERoles;
import com.example.jwt.demo.models.Role;
import java.util.Optional;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface RoleRepository extends JpaRepository<Role, Integer> {

    Optional<Role> findByName(ERoles name);
}
