package com.example.oauth.service;



import jakarta.mail.internet.MimeMessage;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.mail.MailException;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.stereotype.Service;

@Service
public class EmailService {
    private static final Logger logger = LoggerFactory.getLogger(EmailService.class);

    @Autowired
    private JavaMailSender mailSender;

    public void sendOtpEmail(String toEmail, String otp) {
        try {
            MimeMessage message = mailSender.createMimeMessage();
            MimeMessageHelper helper = new MimeMessageHelper(message, true);

            helper.setFrom("your.email@gmail.com");
            helper.setTo(toEmail);
            helper.setSubject("Your OTP Code");
            helper.setText(
                    "<p>Your OTP code is: <strong>" + otp + "</strong></p>" +
                            "<p>This code will expire in 5 minutes.</p>",
                    true  // true indicates HTML content
            );

            mailSender.send(message);
            logger.info("OTP email sent to {}", toEmail);
        } catch (Exception ex) {
            logger.error("Failed to send OTP email to {}", toEmail, ex);
            throw new RuntimeException("Failed to send OTP email", ex);
        }
    }
}