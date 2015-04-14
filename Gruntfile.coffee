module.exports = (grunt) ->
	grunt.initConfig
		shell:
			go:
				command: "go vet && go test"
				options:
					stderr: false
		watch:
			test:
				files: ["*.go"]
				tasks: ["shell:go"]

		for plugin in [
			'grunt-contrib-watch'
			'grunt-shell']
			grunt.loadNpmTasks plugin

		grunt.registerTask "default", [
			"watch"
		]