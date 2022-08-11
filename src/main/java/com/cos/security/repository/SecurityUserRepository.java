package com.cos.security.repository;

import org.springframework.data.jpa.repository.JpaRepository;

import com.cos.security.model.SecurityUser;

public interface SecurityUserRepository extends JpaRepository<SecurityUser, Integer>{

	public SecurityUser findByUsername(String username);
}
