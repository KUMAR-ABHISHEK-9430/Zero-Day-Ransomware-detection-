package main

import (
	"errors"
	"fmt"
	"time"
)

// Task status enum definition
type TaskStatus string

const (
	StatusPending    TaskStatus = "Pending"
	StatusInProgress TaskStatus = "In Progress"
	StatusCompleted  TaskStatus = "Completed"
)

// Task structure representing a system activity tracker
type Task struct {
	ID          int
	Title       string
	Description string
	Status      TaskStatus
	CreatedAt   time.Time
}

// Manager structure holds slices of tasks
type TaskManager struct {
	Tasks []Task
}

// Method to add task
func (tm *TaskManager) AddTask(title string, desc string) Task {
	newTask := Task{
		ID:          len(tm.Tasks) + 1,
		Title:       title,
		Description: desc,
		Status:      StatusPending,
		CreatedAt:   time.Now(),
	}
	tm.Tasks = append(tm.Tasks, newTask)
	return newTask
}

// Method to update task status
func (tm *TaskManager) UpdateStatus(id int, status TaskStatus) error {
	for i, task := range tm.Tasks {
		if task.ID == id {
			tm.Tasks[i].Status = status
			return nil
		}
	}
	return errors.New("task not found")
}

// Method to filter tasks by status
func (tm *TaskManager) GetTasksByStatus(status TaskStatus) []Task {
	var filtered []Task
	for _, task := range tm.Tasks {
		if task.Status == status {
			filtered = append(filtered, task)
		}
	}
	return filtered
}

// Print task summary utility function
func (tm *TaskManager) PrintSummary() {
	fmt.Printf("\n--- TASK MANAGER SUMMARY ---\n")
	fmt.Printf("Total Tasks Tracked: %d\n", len(tm.Tasks))
	for _, t := range tm.Tasks {
		fmt.Printf("[%d] %-15s | Status: %-12s | Created: %s\n", 
			t.ID, t.Title, t.Status, t.CreatedAt.Format("2006-01-02 15:04:05"))
	}
	fmt.Println("---------------------------")
}

func main() {
	fmt.Println("Starting Task Manager Orchestrator...")
	manager := &TaskManager{}

	// Seeding Initial Tasks
	manager.AddTask("Initialize ETW", "Set up Windows Event Tracing providers.")
	manager.AddTask("Setup Data Dir", "Create simulated folder structure with office documents.")
	manager.AddTask("Start Telemetry", "Deploy AegisStream telemetry ingress agent.")
	manager.AddTask("Verify System", "Check logging performance and memory efficiency.")

	// Simulating workflow pipeline activity
	time.Sleep(100 * time.Millisecond)
	err := manager.UpdateStatus(1, StatusInProgress)
	if err != nil {
		fmt.Println("Error:", err)
	}

	err = manager.UpdateStatus(2, StatusCompleted)
	if err != nil {
		fmt.Println("Error:", err)
	}

	err = manager.UpdateStatus(3, StatusInProgress)
	if err != nil {
		fmt.Println("Error:", err)
	}

	// Retrieve pending jobs
	pendings := manager.GetTasksByStatus(StatusPending)
	fmt.Printf("Found %d pending tasks to process:\n", len(pendings))
	for _, pt := range pendings {
		fmt.Printf(" - Task #%d: %s\n", pt.ID, pt.Title)
	}

	// Print manager status report
	manager.PrintSummary()
	fmt.Println("Task manager execution sequence complete.")
}
