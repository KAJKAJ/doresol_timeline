//  Generated on 2014-06-30 using generator-angular-fullstack 1.4.3
'use strict';

// # Globbing
// for performance reasons we're only matching one level down:
// 'test/spec/{,*/}*.js'
// use this if you want to recursively match all subfolders:
// 'test/spec/**/*.js'

module.exports = function (grunt) {

  // Load grunt tasks automatically
  require('load-grunt-tasks')(grunt);

  // Time how long tasks take. Can help when optimizing build times
  require('time-grunt')(grunt);

  // Define the configuration for all the tasks
  grunt.initConfig({
    sourceFolder: 'source',
    distFolder: 'build',

    // Empties folders to start fresh
    clean: {
      dist: {
        files: [{
          dot: true,
          src: [
            '<%= distFolder %>',            
          ]
        }]
      },
      server: '<%= distFolder %>'
    },

    //concat source files
    concat: {
      options: {
        separator: ';',
      },
      dist: {
        src: [
          '<%= sourceFolder %>/js/Core/Library/**/*.js',
         
          '<%= sourceFolder %>/js/Core/Core/VMM.js',
          '<%= sourceFolder %>/js/Core/Core/VMM.Library.js',
          '<%= sourceFolder %>/js/Core/Core/VMM.Browser.js',
          '<%= sourceFolder %>/js/Core/Core/VMM.FileExtention.js',
          '<%= sourceFolder %>/js/Core/Core/VMM.Date.js',
          '<%= sourceFolder %>/js/Core/Core/VMM.Util.js',
          '<%= sourceFolder %>/js/Core/Core/VMM.LoadLib.js',
          '<%= sourceFolder %>/js/Core/Core/VMM.Language.js',

          '<%= sourceFolder %>/js/Core/Language/VMM.Language.js',

          '<%= sourceFolder %>/js/Core/Media/VMM.ExternalAPI.js',
          '<%= sourceFolder %>/js/Core/Media/VMM.MediaElement.js',
          '<%= sourceFolder %>/js/Core/Media/VMM.MediaType.js',
          '<%= sourceFolder %>/js/Core/Media/VMM.TextElement.js',          

          '<%= sourceFolder %>/js/Core/Slider/VMM.DragSlider.js',
          '<%= sourceFolder %>/js/Core/Slider/VMM.Slider.js',
          '<%= sourceFolder %>/js/Core/Slider/VMM.Slider.Slide.js',
          '<%= sourceFolder %>/js/Core/VMM.StoryJS.js',

          '<%= sourceFolder %>/js/VMM.Timeline.js',
          '<%= sourceFolder %>/js/VMM.Timeline.DataObj.js',
          '<%= sourceFolder %>/js/VMM.Timeline.TimeNav.js',
          '<%= sourceFolder %>/js/VMM.Timeline.Min.js', 

          '<%= sourceFolder %>/js/Core/Embed/Embed.LoadLib.js',
          // '<%= sourceFolder %>/js/Core/Embed/Embed.CDN.Generator.js',
          // '<%= sourceFolder %>/js/Core/Embed/Embed.CDN.js',
          '<%= sourceFolder %>/js/Core/Embed/Embed.js'
        ],
        dest: '<%= distFolder %>/js/timeline.js',
      },
    },

    uglify: {
      js: {
        files: {
          '<%= distFolder %>/js/timeline-min.js': ['<%= distFolder %>/js/timeline.js']
        }
      }
    },

    copy: {
      css: {
        expand: true,
        cwd: '<%= sourceFolder %>/css',
        src: '**',
        dest: '<%= distFolder %>/css'
      }
    },

    less: {
      dist: {
        options: {
          paths: ["<%= sourceFolder %>/less"],
        },
        files: {
          '<%= distFolder %>/css/timeline.css': "<%= sourceFolder %>/less/VMM.Timeline.less"
        }
      }
    }
    // less: {
    //   dist: {
    //     options: {
    //         paths: ['<%= sourceFolder %>/less']
    //      },
    //     files: {
    //       '<%= distFolder %>/css/timeline.css': ['**/*.less']
    //     }
    //   }
    // }
  });

  grunt.registerTask('build', [
    'clean:dist',
    'concat:dist',
    'uglify:js',
    'less:dist',
    'copy:css'    
  ]);

  grunt.registerTask('default', [
    'build'    
  ]);
};
