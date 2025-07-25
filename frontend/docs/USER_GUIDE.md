# User Guide

## Overview

Welcome to the Bug Hunting Framework Frontend! This guide will help you understand how to use the application to create and manage bug hunting target profiles effectively.

## Getting Started

### Accessing the Application

1. **Open your web browser**
2. **Navigate to the application URL**
   - Development: `http://localhost:3000`
   - Production: `https://yourdomain.com`
3. **You'll see the main dashboard**

### First Time Setup

1. **No registration required**: The application works without user accounts
2. **Form data persistence**: Your data is automatically saved as you work
3. **Browser compatibility**: Works best with modern browsers (Chrome, Firefox, Safari, Edge)

## Target Profile Builder

### What is a Target Profile?

A target profile is a comprehensive configuration for a bug hunting target that includes:
- **Basic Information**: Target name and domain
- **Platform Details**: Bug bounty platform and program information
- **Scope Configuration**: In-scope and out-scope domains/subdomains
- **Rate Limits**: API rate limiting rules
- **Additional Rules**: Custom rules and requirements

### Creating a New Target Profile

#### Step 1: Basic Information

1. **Target Name**
   - Enter a descriptive name for your target
   - Example: "Acme Corporation Web Application"
   - This helps you identify the target later

2. **Domain**
   - Enter the main domain of your target
   - Example: `example.com`
   - Must be a valid domain format

3. **Validation**
   - The form validates your input in real-time
   - Error messages appear below fields if there are issues
   - You cannot proceed until all errors are resolved

#### Step 2: Program Details

1. **Platform Selection**
   - Choose from supported bug bounty platforms:
     - **HackerOne**: Most popular platform
     - **Bugcrowd**: Large community platform
     - **Intigriti**: European-focused platform
     - **YesWeHack**: European platform
     - **Synack**: Invitation-only platform
     - **CrowdStrike**: Enterprise-focused
     - **Federacy**: Newer platform
     - **OpenBugBounty**: Free platform
     - **HackenProof**: Eastern European platform
     - **Anonymous**: For private programs

2. **Program URL** (Optional)
   - Enter the URL to the bug bounty program page
   - Example: `https://hackerone.com/acme-corp`
   - Helps with documentation and reference

3. **Program ID** (Optional)
   - Enter the program identifier if known
   - Example: `acme-corp` or `12345`
   - Useful for API integrations

#### Step 3: Scope Configuration

1. **In-Scope Domains**
   - Add domains and subdomains that are in scope
   - Use wildcards for broader scope: `*.example.com`
   - Examples:
     - `example.com` (main domain)
     - `api.example.com` (API subdomain)
     - `*.example.com` (all subdomains)
     - `test.example.com` (specific subdomain)

2. **Out-Scope Domains**
   - Add domains that are explicitly out of scope
   - Examples:
     - `admin.example.com` (admin panel)
     - `staging.example.com` (staging environment)
     - `*.staging.example.com` (all staging subdomains)

3. **Scope Management**
   - **Add Entry**: Click "Add Entry" to add new scope items
   - **Remove Entry**: Click the "X" button to remove items
   - **Bulk Import**: Paste multiple domains separated by newlines
   - **Validation**: Invalid domains will be highlighted

#### Step 4: Rate Limits

1. **Rate Limit Configuration**
   - Define API rate limiting rules
   - Helps prevent accidental rate limit violations
   - Examples:
     - `/api/*` - 60 requests per minute
     - `/auth/*` - 10 requests per minute
     - `/*` - 100 requests per minute

2. **Adding Rate Limits**
   - **Endpoint Pattern**: Enter the endpoint pattern (e.g., `/api/*`)
   - **Requests per Minute**: Set the rate limit
   - **Add Rule**: Click "Add Rule" to add the rate limit

3. **Rate Limit Templates**
   - **Conservative**: Lower limits for sensitive endpoints
   - **Standard**: Default limits for most endpoints
   - **Aggressive**: Higher limits for testing

#### Step 5: Additional Rules

1. **Custom Rules**
   - Add any additional rules or requirements
   - Examples:
     - "No automated scanning without permission"
     - "Do not test on production data"
     - "Contact security team before testing"
     - "Follow responsible disclosure timeline"

2. **Rule Templates**
   - **Basic**: Standard security testing rules
   - **Comprehensive**: Detailed testing guidelines
   - **Custom**: Write your own rules

3. **Formatting**
   - Use plain text or markdown formatting
   - Character limit: 1000 characters
   - Real-time character count display

#### Step 6: Review and Submit

1. **Review Your Configuration**
   - Review all information before submission
   - Check for any errors or missing information
   - Verify scope configuration is correct

2. **Edit Information**
   - Click "Edit" on any section to make changes
   - Navigate back to previous steps if needed
   - All data is preserved during navigation

3. **Submit Target Profile**
   - Click "Create Target" to submit
   - The system will validate all data
   - You'll receive confirmation of successful creation

## Managing Target Profiles

### Viewing Target Profiles

1. **Dashboard View**
   - See all your created target profiles
   - Basic information displayed in cards
   - Quick access to edit or delete

2. **Detailed View**
   - Click on a target to see full details
   - All configuration information displayed
   - Export options available

### Editing Target Profiles

1. **Access Edit Mode**
   - Click "Edit" on any target profile
   - Navigate through the same step-by-step process
   - All existing data is pre-filled

2. **Making Changes**
   - Modify any field as needed
   - Add or remove scope entries
   - Update rate limits or rules

3. **Saving Changes**
   - Click "Update Target" to save changes
   - Changes are immediately applied
   - No data loss during editing

### Deleting Target Profiles

1. **Confirmation Required**
   - Click "Delete" on a target profile
   - Confirm deletion in the dialog
   - Deletion cannot be undone

2. **Bulk Operations**
   - Select multiple targets for bulk deletion
   - Use checkboxes to select targets
   - Confirm bulk deletion

## Form Features

### Auto-Save

- **Automatic Saving**: Your form data is saved automatically as you type
- **No Data Loss**: Close the browser and return later - your data is preserved
- **Multiple Sessions**: Work on multiple targets simultaneously

### Validation

- **Real-time Validation**: Errors appear as you type
- **Field-specific Validation**: Each field has specific validation rules
- **Step Validation**: Cannot proceed to next step with errors
- **Final Validation**: Complete validation before submission

### Navigation

- **Step Navigation**: Use "Next" and "Back" buttons to navigate
- **Progress Indicator**: Visual progress bar shows current step
- **Keyboard Navigation**: Use Tab and Enter keys for navigation
- **Mobile Friendly**: Touch-friendly navigation on mobile devices

### Error Handling

- **Clear Error Messages**: Descriptive error messages explain issues
- **Error Recovery**: Fix errors and continue where you left off
- **Validation Help**: Hover over error icons for additional help
- **Form Recovery**: Form data is preserved even with validation errors

## Platform-Specific Features

### HackerOne Integration

- **Program URL Format**: `https://hackerone.com/[program-name]`
- **Scope Format**: Compatible with HackerOne scope format
- **Rate Limits**: Aligned with HackerOne rate limiting guidelines

### Bugcrowd Integration

- **Program URL Format**: `https://bugcrowd.com/[program-name]`
- **Scope Format**: Compatible with Bugcrowd scope format
- **Additional Fields**: Program-specific fields available

### Intigriti Integration

- **Program URL Format**: `https://app.intigriti.com/programs/[program-name]`
- **European Focus**: Optimized for European programs
- **GDPR Compliance**: Built-in privacy considerations

## Best Practices

### Scope Configuration

1. **Be Specific**
   - Use specific subdomains when possible
   - Avoid overly broad wildcards
   - Document out-of-scope areas clearly

2. **Regular Updates**
   - Update scope as programs change
   - Remove outdated entries
   - Add new subdomains as discovered

3. **Documentation**
   - Add notes about special considerations
   - Document any program-specific rules
   - Keep track of scope changes

### Rate Limit Management

1. **Conservative Approach**
   - Start with lower rate limits
   - Increase limits as needed
   - Monitor for rate limit violations

2. **Endpoint-Specific Limits**
   - Set different limits for different endpoints
   - Be more restrictive with authentication endpoints
   - Allow higher limits for static content

3. **Testing and Adjustment**
   - Test rate limits in development
   - Adjust based on actual usage
   - Monitor for false positives

### Rule Documentation

1. **Clear and Concise**
   - Write rules in simple language
   - Avoid technical jargon
   - Use bullet points for readability

2. **Comprehensive Coverage**
   - Cover all important aspects
   - Include contact information
   - Specify timeline requirements

3. **Regular Review**
   - Review and update rules regularly
   - Remove outdated information
   - Add new requirements as needed

## Troubleshooting

### Common Issues

1. **Form Won't Submit**
   - Check for validation errors
   - Ensure all required fields are filled
   - Verify domain format is correct

2. **Data Not Saving**
   - Check browser storage settings
   - Ensure cookies are enabled
   - Try refreshing the page

3. **Validation Errors**
   - Read error messages carefully
   - Check field format requirements
   - Use the help text for guidance

### Getting Help

1. **Documentation**
   - Check this user guide
   - Review the FAQ section
   - Look for help tooltips

2. **Support**
   - Create an issue on GitHub
   - Use GitHub Discussions
   - Contact the development team

3. **Feature Requests**
   - Suggest new features
   - Report bugs or issues
   - Provide feedback on usability

## Keyboard Shortcuts

### Navigation
- **Tab**: Move to next field
- **Shift + Tab**: Move to previous field
- **Enter**: Submit form or move to next step
- **Escape**: Cancel current action

### Form Actions
- **Ctrl + S**: Save form data (auto-save is enabled)
- **Ctrl + Z**: Undo last action (if supported)
- **Ctrl + Y**: Redo last action (if supported)

### Accessibility
- **Alt + 1-6**: Navigate to specific steps
- **Alt + N**: Next step
- **Alt + B**: Previous step
- **Alt + S**: Submit form

## Mobile Usage

### Touch Interface
- **Tap**: Select fields and buttons
- **Swipe**: Navigate between steps (if enabled)
- **Pinch**: Zoom in/out on content
- **Long Press**: Context menus (if available)

### Mobile Optimization
- **Responsive Design**: Optimized for all screen sizes
- **Touch Targets**: Large enough for easy tapping
- **Virtual Keyboard**: Optimized for mobile keyboards
- **Offline Support**: Works without internet connection

## Data Privacy

### Data Storage
- **Local Storage**: Data stored in your browser
- **No Server Storage**: Data not sent to servers unless submitted
- **Privacy**: Your data remains private
- **Export**: Export your data at any time

### Data Export
- **JSON Format**: Export in standard JSON format
- **CSV Format**: Export in CSV format for spreadsheets
- **Backup**: Regular backups recommended
- **Portability**: Data can be imported to other systems

## Updates and Changes

### Version Updates
- **Automatic Updates**: Application updates automatically
- **Feature Announcements**: New features announced in-app
- **Changelog**: Complete list of changes available
- **Backward Compatibility**: Updates maintain data compatibility

### Migration
- **Data Migration**: Automatic migration of old data formats
- **Backup**: Always backup before major updates
- **Rollback**: Ability to revert to previous versions
- **Support**: Migration support available

## Conclusion

The Bug Hunting Framework Frontend provides a comprehensive solution for creating and managing bug hunting target profiles. With its intuitive interface, robust validation, and powerful features, you can efficiently manage your bug hunting activities.

### Key Benefits
- **Efficiency**: Streamlined workflow saves time
- **Accuracy**: Validation prevents errors
- **Organization**: Centralized management of targets
- **Flexibility**: Adaptable to different platforms and requirements

### Getting Started
1. Create your first target profile
2. Explore the different features
3. Customize settings for your needs
4. Build a library of target profiles

### Support
- **Documentation**: Comprehensive guides available
- **Community**: Active user community
- **Development**: Regular updates and improvements
- **Feedback**: Your input helps improve the application

Thank you for using the Bug Hunting Framework Frontend! 