package com.example.demo.student;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Arrays;
import java.util.List;

@RestController
@RequestMapping("/api/v1/students")
public class StudentController {

    private static List<Student> students = Arrays.asList(
            new Student (1, "John Smith"),
            new Student (2, "Mary Smith"),
            new Student (3, "Richard Smith")
    );

    @GetMapping(path = "{student_id}")
    public Student getStudent(@PathVariable("student_id") Integer student_id) {
        return students.stream()
                .filter(student -> student_id.equals(student.getStudent_id()))
                .findFirst()
                .orElseThrow(() -> new IllegalStateException("Student " + student_id + " does not exist!"));
    }
}
