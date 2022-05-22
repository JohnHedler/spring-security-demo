package com.example.demo.student;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.Arrays;
import java.util.List;

@RestController
@RequestMapping("management/api/v1/students")
public class StudentManagementController {

    private static List<Student> students = Arrays.asList(
            new Student (1, "John Smith"),
            new Student (2, "Mary Smith"),
            new Student (3, "Richard Smith")
    );

    // hasRole('ROLE_') hasAnyRole('ROLE_') hasAuthority('permission') hasAnyAuthority('permission')

    @GetMapping
    @PreAuthorize("hasAnyRole('ROLE_ADMIN', 'ROLE_ADMINTRAINEE')")
    public List<Student> getAllStudents() {
        System.out.println("getAllStudents method: ");
        return students;
    }

    @PostMapping
    @PreAuthorize("hasAuthority('student:write')")
    public void registerNewStudent(@RequestBody Student student) {
        System.out.print("registerNewStudent method: ");
        System.out.println(student);
    }

    @DeleteMapping(path = "{student_id}")
    @PreAuthorize("hasAuthority('student:write')")
    public void deleteStudent(@PathVariable Integer student_id) {
        System.out.print("deleteStudent method: ");
        System.out.println(student_id);
    }

    @PutMapping(path = "{student_id}")
    @PreAuthorize("hasAuthority('student:write')")
    public void updateStudent(@PathVariable("student_id") Integer student_id, @RequestBody Student student) {
        System.out.print("updateStudent method: ");
        System.out.println(String.format("%s %s", student_id, student));
    }
}
